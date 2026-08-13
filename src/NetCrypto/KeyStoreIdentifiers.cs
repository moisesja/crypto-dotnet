using System.Text;

namespace NetCrypto;

/// <summary>
/// The least-privilege scope a capable key store instance operates within. One backend
/// (an HSM partition, a cloud KMS account, a database) commonly serves many tenants or
/// profiles; an <see cref="ICapableKeyStore"/> instance sees only the keys in its own
/// namespace and cannot get, list, sign with, agree with, or delete another namespace's
/// keys — scoping is a contract property, not an alias-prefix naming convention, because
/// naming is not authorization.
/// </summary>
/// <remarks>
/// The namespace is also part of mutation identity: the same <see cref="KeyOperationId"/>
/// used in two different namespaces addresses two different operations and must not collide.
/// </remarks>
/// <param name="Value">
/// The backend-defined scope identifier. Must be non-empty, at most
/// 512 characters, and free of control characters.
/// </param>
public readonly record struct KeyStoreNamespaceId(string Value)
{
    private readonly string _value = KeyStoreIdentifier.Validate(Value, nameof(Value), "namespace id");

    /// <inheritdoc cref="KeyStoreNamespaceId" />
    /// <remarks>
    /// Validated on the <c>init</c> accessor, not merely in the constructor, so a
    /// <c>with</c> expression cannot install a value the constructor would have rejected.
    /// </remarks>
    public string Value
    {
        get => _value;
        init => _value = KeyStoreIdentifier.Validate(value, nameof(Value), "namespace id");
    }

    /// <summary>The raw identifier, or the empty string for a <c>default</c> instance.</summary>
    public override string ToString() => Value ?? string.Empty;
}

/// <summary>
/// Immutable identity of one <em>key instance</em> inside a store — the concept an alias
/// cannot supply.
/// </summary>
/// <remarks>
/// <para>
/// Aliases are reusable: a key can be deleted and a different key created under the same
/// name, and a KMS alias can be re-bound to a different key version. Every generate and
/// import therefore mints a fresh instance id, deleting a key makes its id permanently
/// unusable, and re-creating the alias yields a <em>different</em> id. Passing a stale id
/// in a <see cref="KeySignRequest"/>, <see cref="KeyBbsSignRequest"/> or
/// <see cref="KeyAgreementRequest"/> fails instead of silently signing under whatever key
/// now answers to the alias.
/// </para>
/// <para>
/// This generalizes to the whole custody surface the alias-rebinding defense that
/// <see cref="KeyStoreSigner"/> applies on the recoverable-signing path (issue #21), where
/// it is only possible because a recoverable signature encodes its own signer.
/// </para>
/// </remarks>
/// <param name="Value">
/// The store-minted identifier. Must be non-empty, at most 512 characters, and free of
/// control characters. Never reused within a store's lifetime, including after deletion.
/// </param>
public readonly record struct KeyInstanceId(string Value)
{
    private readonly string _value = KeyStoreIdentifier.Validate(Value, nameof(Value), "key instance id");

    /// <inheritdoc cref="KeyInstanceId" />
    /// <remarks>
    /// Validated on the <c>init</c> accessor, not merely in the constructor, so a
    /// <c>with</c> expression cannot install a value the constructor would have rejected.
    /// </remarks>
    public string Value
    {
        get => _value;
        init => _value = KeyStoreIdentifier.Validate(value, nameof(Value), "key instance id");
    }

    /// <summary>The raw identifier, or the empty string for a <c>default</c> instance.</summary>
    public override string ToString() => Value ?? string.Empty;
}

/// <summary>
/// A caller-minted idempotency key for a store mutation.
/// </summary>
/// <remarks>
/// Cloud mutations fail ambiguously — the request is accepted but the acknowledgement is
/// lost. Retrying a generate then double-creates (and double-bills); retrying an import
/// re-transmits private key material that may already have been accepted. Tagging the
/// mutation with an operation id makes the retry safe: mutation identity is
/// <c>(<see cref="KeyStoreNamespaceId"/>, <see cref="KeyMutationKind"/>, <see cref="KeyOperationId"/>)</c>,
/// a repeat of the same request returns the original result with
/// <see cref="KeyMutationResult.Replayed"/> set, and a <em>different</em> request under the
/// same id is rejected with <see cref="KeyStoreError.IdempotencyConflict"/> rather than
/// silently overwriting.
/// </remarks>
/// <param name="Value">
/// The caller's identifier — a GUID or ULID is the usual choice. Must be non-empty, at most
/// 512 characters, and free of control characters. Mint a fresh one per logical operation
/// and reuse it across retries of <em>that</em> operation only.
/// </param>
public readonly record struct KeyOperationId(string Value)
{
    private readonly string _value = KeyStoreIdentifier.Validate(Value, nameof(Value), "key operation id");

    /// <inheritdoc cref="KeyOperationId" />
    /// <remarks>
    /// Validated on the <c>init</c> accessor, not merely in the constructor, so a
    /// <c>with</c> expression cannot install a value the constructor would have rejected.
    /// </remarks>
    public string Value
    {
        get => _value;
        init => _value = KeyStoreIdentifier.Validate(value, nameof(Value), "key operation id");
    }

    /// <summary>The raw identifier, or the empty string for a <c>default</c> instance.</summary>
    public override string ToString() => Value ?? string.Empty;
}

/// <summary>
/// A stable string identifier for one concrete store operation — curve, hash, and, for
/// ECDSA, the <em>observable signature encoding</em>.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately a string rather than a closed enum: a backend may support algorithms
/// NetCrypto has never heard of, and a closed enum would force every such backend to lie.
/// The identifiers this library mints and understands are the constants on
/// <see cref="KeyStoreAlgorithms"/>; vendor marketing names are not identifiers.
/// </para>
/// <para>
/// The identifier binds the encoding, which is what makes format selection reachable for a
/// stored key at all: <see cref="KeyStoreAlgorithms.Es256Der"/> and
/// <see cref="KeyStoreAlgorithms.Es256P1363"/> are the same curve and hash but different
/// wire bytes, and JOSE/JWS/COSE/WebAuthn mandate the latter while X.509/CMS use the former.
/// </para>
/// </remarks>
/// <param name="Value">
/// The identifier. Must be non-empty, at most 512 characters, and free of control
/// characters. Compared with ordinal equality — identifiers are case-sensitive.
/// </param>
public readonly record struct KeyStoreAlgorithmId(string Value)
{
    private readonly string _value = KeyStoreIdentifier.Validate(Value, nameof(Value), "algorithm id");

    /// <inheritdoc cref="KeyStoreAlgorithmId" />
    /// <remarks>
    /// Validated on the <c>init</c> accessor, not merely in the constructor, so a
    /// <c>with</c> expression cannot install a value the constructor would have rejected.
    /// </remarks>
    public string Value
    {
        get => _value;
        init => _value = KeyStoreIdentifier.Validate(value, nameof(Value), "algorithm id");
    }

    /// <summary>The raw identifier, or the empty string for a <c>default</c> instance.</summary>
    public override string ToString() => Value ?? string.Empty;
}

/// <summary>
/// Shared validation for the key-store identifier value types, and the re-validation used at
/// every consuming member.
/// </summary>
/// <remarks>
/// <para>
/// A <c>readonly record struct</c> always has a <c>default</c> value whose <c>Value</c> is
/// <c>null</c>. That hole is not closable by the type itself, so every member that consumes an
/// identifier re-validates it and reports the failure against its own parameter name (NFR-3).
/// (The <c>with</c>-expression hole <em>is</em> closable, and is closed: each identifier
/// validates on its <c>init</c> accessor rather than only in a property initializer, which a
/// <c>with</c> would skip.)
/// </para>
/// <para>
/// Ill-formed UTF-16 is rejected here rather than left to a downstream encoder.
/// <c>Encoding.UTF8</c> uses replacement fallback, so every unpaired surrogate — and U+FFFD
/// itself — encodes to the same three bytes. Any identifier that reaches a UTF-8 encoding
/// (a mutation fingerprint, a backend's wire format, a log line) would then be indistinguishable
/// from a different identifier, which is how one caller's mutation silently replays another's.
/// Well-formed surrogate <em>pairs</em> stay legal, so astral-plane aliases keep working.
/// </para>
/// </remarks>
internal static class KeyStoreIdentifier
{
    internal const int MaxLength = 512;

    internal static string Validate(string value, string paramName, string description)
    {
        ArgumentNullException.ThrowIfNull(value, paramName);
        if (value.Length == 0)
            throw new ArgumentException($"A {description} must not be empty.", paramName);
        if (value.Length > MaxLength)
            throw new ArgumentException(
                $"A {description} must be at most {MaxLength} characters, got {value.Length}.", paramName);
        RequireCleanText(value, paramName, $"A {description}");
        return value;
    }

    /// <summary>
    /// Re-validates an identifier reached through a request object, reporting any failure
    /// against the calling member's own parameter. Catches the <c>default(T)</c> hole, which
    /// the type cannot close for itself.
    /// </summary>
    internal static void Require(string? value, string paramName, string memberPath)
    {
        if (string.IsNullOrEmpty(value))
            throw new ArgumentException($"{memberPath} must be a non-empty identifier.", paramName);
        if (value.Length > MaxLength)
            throw new ArgumentException(
                $"{memberPath} must be at most {MaxLength} characters, got {value.Length}.", paramName);
        RequireCleanText(value, paramName, memberPath);
    }

    /// <summary>
    /// Validates a store alias: non-empty, well-formed, and within the advertised alias bound,
    /// measured in UTF-8 bytes because that is what a backend actually stores.
    /// </summary>
    internal static void RequireAlias(string? alias, int maxBytes, string paramName, string memberPath)
    {
        ArgumentNullException.ThrowIfNull(alias, paramName);
        if (alias.Length == 0)
            throw new ArgumentException($"{memberPath} must be a non-empty alias.", paramName);
        RequireCleanText(alias, paramName, memberPath);

        var bytes = Encoding.UTF8.GetByteCount(alias);
        if (bytes > maxBytes)
            throw new ArgumentException(
                $"{memberPath} must be at most {maxBytes} UTF-8 bytes, got {bytes}.", paramName);
    }

    private static void RequireCleanText(string value, string paramName, string subject)
    {
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];

            if (char.IsControl(c))
                throw new ArgumentException($"{subject} must not contain control characters.", paramName);

            if (char.IsHighSurrogate(c))
            {
                // A high surrogate must be followed by its low half; anything else is a lone
                // surrogate that UTF-8 encoding would silently replace with U+FFFD.
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                    throw new ArgumentException(
                        $"{subject} must be well-formed UTF-16; it contains an unpaired surrogate.", paramName);
                i++;
                continue;
            }

            if (char.IsLowSurrogate(c))
                throw new ArgumentException(
                    $"{subject} must be well-formed UTF-16; it contains an unpaired surrogate.", paramName);
        }
    }
}
