using System.Collections.ObjectModel;

namespace NetCrypto;

/// <summary>
/// The operations a key store can advertise. Deletion is not listed: a store that can hold a
/// key can always be asked to destroy it, so there is nothing to discover.
/// </summary>
public enum KeyStoreOperation
{
    /// <summary>Create a new key inside the store.</summary>
    Generate,

    /// <summary>Accept externally-generated key material through <see cref="TransferableKeyMaterial"/>.</summary>
    Import,

    /// <summary>Sign a single byte string with a stored key.</summary>
    Sign,

    /// <summary>Perform ECDH against a stored key and return the raw shared secret Z.</summary>
    KeyAgreement,

    /// <summary>Produce a BBS multi-message signature with a stored BLS12-381 G2 key.</summary>
    BbsSign,
}

/// <summary>
/// One thing a store can actually do: a (key type, operation, algorithm) triple together with
/// the finite bound on the input it accepts.
/// </summary>
/// <remarks>
/// <para>
/// Discovery honesty is bidirectional. Every advertised capability must genuinely work, and
/// every combination that is <em>not</em> advertised must fail with
/// <see cref="KeyStoreError.Unsupported"/> before key creation, signing, or agreement — never
/// as a silent downgrade of curve, hash, or encoding.
/// </para>
/// </remarks>
/// <param name="KeyType">The key type this capability applies to.</param>
/// <param name="Operation">The operation this capability describes.</param>
/// <param name="Algorithm">
/// The algorithm identifier, which also binds the observable encoding. Required for
/// <see cref="KeyStoreOperation.Sign"/>, <see cref="KeyStoreOperation.KeyAgreement"/>, and
/// <see cref="KeyStoreOperation.BbsSign"/>; must be <c>null</c> for
/// <see cref="KeyStoreOperation.Generate"/> and <see cref="KeyStoreOperation.Import"/>, which
/// select no algorithm.
/// </param>
/// <param name="MaxInputBytes">
/// The inclusive upper bound, in bytes, on the caller-supplied input this operation accepts.
/// What is measured depends on the operation: the UTF-8 length of the alias for
/// <see cref="KeyStoreOperation.Generate"/> and <see cref="KeyStoreOperation.Import"/>;
/// <see cref="KeySignRequest.Data"/> for <see cref="KeyStoreOperation.Sign"/>;
/// <see cref="KeyAgreementRequest.PeerPublicKey"/> for
/// <see cref="KeyStoreOperation.KeyAgreement"/>; and the total of all
/// <see cref="KeyBbsSignRequest.Messages"/> plus <see cref="KeyBbsSignRequest.Header"/> for
/// <see cref="KeyStoreOperation.BbsSign"/>. Always positive and finite — neither <c>null</c>
/// nor zero is available to mean "unbounded", because an unbounded claim is one a real
/// backend cannot honor.
/// </param>
/// <exception cref="ArgumentException">
/// <paramref name="MaxInputBytes"/> is not positive; <paramref name="Algorithm"/> is absent
/// for an operation that requires one, or present for one that does not; or
/// <paramref name="KeyType"/> / <paramref name="Operation"/> is not a defined enum value.
/// </exception>
public sealed record KeyStoreCapability(
    KeyType KeyType,
    KeyStoreOperation Operation,
    KeyStoreAlgorithmId? Algorithm,
    int MaxInputBytes)
{
    private readonly KeyType _keyType = RequireDefined(KeyType);
    private readonly KeyStoreOperation _operation = RequireDefined(Operation);
    private readonly KeyStoreAlgorithmId? _algorithm = ValidateAlgorithm(Operation, Algorithm);
    private readonly int _maxInputBytes = RequirePositive(MaxInputBytes);

    /// <inheritdoc cref="KeyStoreCapability" />
    /// <remarks>
    /// Every accessor here validates on <c>init</c> rather than only in a property initializer,
    /// because a <c>with</c> expression skips the initializer. A capability is the store's
    /// advertisement about itself; one that can be quietly rewritten into an impossible shape —
    /// a <c>Sign</c> entry with no algorithm, a zero byte bound — advertises nothing.
    /// </remarks>
    public KeyType KeyType
    {
        get => _keyType;
        init => _keyType = RequireDefined(value);
    }

    /// <inheritdoc cref="KeyStoreCapability" />
    /// <remarks>
    /// The <c>init</c> accessor also re-validates the operation–algorithm pairing against the
    /// current <see cref="Algorithm"/>: mutating the operation alone must not leave an algorithm
    /// on a Generate/Import capability, or strip the one a Sign/KeyAgreement/BbsSign capability
    /// requires. A consequence is that a <c>with</c> expression cannot change
    /// <see cref="Operation"/> and <see cref="Algorithm"/> across that divide in either order —
    /// construct a new capability instead.
    /// </remarks>
    public KeyStoreOperation Operation
    {
        get => _operation;
        init
        {
            var defined = RequireDefined(value);
            ValidateAlgorithm(defined, _algorithm);
            _operation = defined;
        }
    }

    /// <inheritdoc cref="KeyStoreCapability" />
    public KeyStoreAlgorithmId? Algorithm
    {
        get => _algorithm;
        init => _algorithm = ValidateAlgorithm(Operation, value);
    }

    /// <inheritdoc cref="KeyStoreCapability" />
    public int MaxInputBytes
    {
        get => _maxInputBytes;
        init => _maxInputBytes = RequirePositive(value);
    }

    private static KeyType RequireDefined(KeyType keyType) => Enum.IsDefined(keyType)
        ? keyType
        : throw new ArgumentException(
            $"Key type {(int)keyType} is not a defined {nameof(NetCrypto.KeyType)}.", nameof(KeyType));

    private static KeyStoreOperation RequireDefined(KeyStoreOperation operation) => Enum.IsDefined(operation)
        ? operation
        : throw new ArgumentException(
            $"Operation {(int)operation} is not a defined {nameof(KeyStoreOperation)}.", nameof(Operation));

    private static int RequirePositive(int maxInputBytes) => maxInputBytes > 0
        ? maxInputBytes
        : throw new ArgumentException(
            $"A capability's maximum input size must be positive and finite, got {maxInputBytes}.",
            nameof(MaxInputBytes));

    private static KeyStoreAlgorithmId? ValidateAlgorithm(KeyStoreOperation operation, KeyStoreAlgorithmId? algorithm)
    {
        var required = operation is KeyStoreOperation.Sign or KeyStoreOperation.KeyAgreement or KeyStoreOperation.BbsSign;
        if (required && algorithm is null)
            throw new ArgumentException($"Operation {operation} requires an algorithm identifier.", nameof(algorithm));
        if (!required && algorithm is not null)
            throw new ArgumentException($"Operation {operation} selects no algorithm; the identifier must be null.", nameof(algorithm));
        if (algorithm is { } id)
            KeyStoreIdentifier.Require(id.Value, nameof(algorithm), $"{nameof(KeyStoreCapability)}.{nameof(Algorithm)}");
        return algorithm;
    }
}

/// <summary>
/// A store's complete, deeply immutable self-description: everything it can do, and nothing
/// it cannot.
/// </summary>
/// <remarks>
/// <para>
/// Discovery is side-effect-free and safe to call repeatedly. <see cref="Revision"/> is stable
/// for the lifetime of the store instance that produced it — a store whose capabilities change
/// (a re-configured HSM partition, a rotated KMS policy) is reached through a new instance, so
/// a caller that validated once against a revision can keep trusting it for as long as it holds
/// the handle. A temporary backend outage is reported as
/// <see cref="KeyStoreError.Unavailable"/>, never as an empty capability set, because an empty
/// set is indistinguishable from "this backend can do nothing" and would make a caller
/// permanently reroute around a store that is merely down.
/// </para>
/// </remarks>
/// <param name="Revision">
/// An opaque token identifying this exact capability snapshot. Equal revisions from the same
/// store mean equal capabilities.
/// </param>
/// <param name="Capabilities">
/// Every advertised capability. Copied on construction, so neither the caller's list nor any
/// later mutation of it can change what a store advertised.
/// </param>
/// <exception cref="ArgumentException">
/// <paramref name="Revision"/> is empty, <paramref name="Capabilities"/> contains a
/// <c>null</c>, or two entries describe the same (key type, operation, algorithm) triple.
/// </exception>
/// <exception cref="ArgumentNullException"><paramref name="Capabilities"/> is <c>null</c>.</exception>
public sealed record KeyStoreCapabilitySet(string Revision, IReadOnlyList<KeyStoreCapability> Capabilities)
{
    private readonly string _revision = KeyStoreIdentifier.Validate(Revision, nameof(Revision), "capability revision");
    private readonly IReadOnlyList<KeyStoreCapability> _capabilities = Freeze(Capabilities);

    /// <inheritdoc cref="KeyStoreCapabilitySet" />
    public string Revision
    {
        get => _revision;
        init => _revision = KeyStoreIdentifier.Validate(value, nameof(Revision), "capability revision");
    }

    /// <inheritdoc cref="KeyStoreCapabilitySet" />
    /// <remarks>
    /// Copied and frozen on <c>init</c>, not merely in the constructor: a <c>with</c> expression
    /// skips a property initializer, and one that installed the caller's live list — or a list
    /// containing <c>null</c> — would leave the caller holding a handle to what the store
    /// "advertises", and would turn <see cref="Find"/> into a <c>NullReferenceException</c>.
    /// </remarks>
    public IReadOnlyList<KeyStoreCapability> Capabilities
    {
        get => _capabilities;
        init => _capabilities = Freeze(value);
    }

    /// <summary>
    /// Finds the advertised capability for a (key type, operation, algorithm) triple, or
    /// <c>null</c> when the store does not advertise it.
    /// </summary>
    /// <remarks>
    /// This is the "validate, then act" half of discovery: a caller that finds no capability
    /// here knows the operation would be refused with <see cref="KeyStoreError.Unsupported"/>,
    /// and can route the key elsewhere without a failed round-trip. It also yields the
    /// <see cref="KeyStoreCapability.MaxInputBytes"/> bound to check the payload against.
    /// </remarks>
    /// <param name="keyType">The key type to look for.</param>
    /// <param name="operation">The operation to look for.</param>
    /// <param name="algorithm">
    /// The algorithm identifier; pass <c>null</c> for <see cref="KeyStoreOperation.Generate"/>
    /// and <see cref="KeyStoreOperation.Import"/>, which select no algorithm.
    /// </param>
    /// <returns>The matching capability, or <c>null</c>.</returns>
    public KeyStoreCapability? Find(KeyType keyType, KeyStoreOperation operation, KeyStoreAlgorithmId? algorithm = null)
    {
        foreach (var capability in Capabilities)
        {
            if (capability.KeyType == keyType
                && capability.Operation == operation
                && Nullable.Equals(capability.Algorithm, algorithm))
            {
                return capability;
            }
        }

        return null;
    }

    /// <summary>
    /// Value equality over <see cref="Revision"/> and the <em>contents</em> of
    /// <see cref="Capabilities"/>. The record-synthesized comparison would compare the list by
    /// reference, making two identical snapshots unequal.
    /// </summary>
    public bool Equals(KeyStoreCapabilitySet? other) =>
        other is not null
        && string.Equals(Revision, other.Revision, StringComparison.Ordinal)
        && Capabilities.Count == other.Capabilities.Count
        && Capabilities.SequenceEqual(other.Capabilities);

    /// <summary>Hash code consistent with the content-based <see cref="Equals(KeyStoreCapabilitySet)"/>.</summary>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Revision, StringComparer.Ordinal);
        foreach (var capability in Capabilities)
            hash.Add(capability);
        return hash.ToHashCode();
    }

    private static IReadOnlyList<KeyStoreCapability> Freeze(IReadOnlyList<KeyStoreCapability> capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);

        var copy = new List<KeyStoreCapability>(capabilities.Count);
        var seen = new HashSet<(KeyType, KeyStoreOperation, string?)>();
        foreach (var capability in capabilities)
        {
            if (capability is null)
                throw new ArgumentException("A capability set must not contain null entries.", nameof(capabilities));
            if (!seen.Add((capability.KeyType, capability.Operation, capability.Algorithm?.Value)))
                throw new ArgumentException(
                    $"Duplicate capability for {capability.KeyType}/{capability.Operation}" +
                    $"{(capability.Algorithm is { } a ? $"/{a.Value}" : string.Empty)}.",
                    nameof(capabilities));
            copy.Add(capability);
        }

        return new ReadOnlyCollection<KeyStoreCapability>(copy);
    }
}

/// <summary>
/// Self-description for a key store: what it can actually do, discoverable before first use.
/// </summary>
/// <remarks>
/// Backends support different curves, operations, and encodings depending on how they are
/// configured — an HSM partition without BLS, a KMS account without X25519. Without discovery
/// the first sign or generate is the probe, and it fails at runtime in production. This
/// generalizes the one capability probe NetCrypto already had,
/// <see cref="IBbsCryptoProvider.IsAvailable"/>.
/// </remarks>
public interface IKeyStoreCapabilityProvider
{
    /// <summary>
    /// Returns the store's capability snapshot. Side-effect-free, safe to call repeatedly, and
    /// deeply immutable.
    /// </summary>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>The capability set; never empty and never <c>null</c>.</returns>
    /// <exception cref="KeyStoreException">
    /// The backend is temporarily unreachable (<see cref="KeyStoreError.Unavailable"/>), is
    /// throttling (<see cref="KeyStoreError.Throttled"/>), or refuses the caller
    /// (<see cref="KeyStoreError.AccessDenied"/>). An outage is reported here rather than as
    /// an empty capability set.
    /// </exception>
    Task<KeyStoreCapabilitySet> GetCapabilitiesAsync(CancellationToken ct = default);
}
