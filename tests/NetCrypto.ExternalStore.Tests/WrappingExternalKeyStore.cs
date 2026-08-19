using NetCrypto;

namespace NetCrypto.ExternalStore.Tests;

/// <summary>
/// The smallest honest out-of-assembly <see cref="ICapableKeyStore"/>: it advertises exactly one
/// capability — Ed25519 import — and implements the routed import through
/// <see cref="TransferableKeyMaterial.Consume{T}"/>, in the shape issue #28 was raised from (a
/// BYOK ceremony that must read the private key exactly once to wrap it for a remote custodian,
/// then never see it again).
/// </summary>
/// <remarks>
/// <para>
/// Every other member throws: this is not a reference store and must never be mistaken for one.
/// The point of the type is the <em>compile</em>: an assembly with no
/// <c>InternalsVisibleTo</c> grant can implement the import half of the contract at all.
/// </para>
/// <para>
/// <b>The "wrap" is a stand-in, not cryptography.</b> A real custody provider would wrap under
/// AES-KWP + RSA-OAEP against the custodian's wrapping key. Here it is a keyed XOR, chosen
/// precisely because it is trivially invertible: a test can unwrap and assert the exact secret
/// bytes crossed the boundary, which is what distinguishes "the store read the key" from "the
/// store read a zeroized buffer".
/// </para>
/// </remarks>
public sealed class WrappingExternalKeyStore : ICapableKeyStore
{
    private static readonly DefaultKeyGenerator Generator = new();

    private readonly byte[] _wrappingKey;
    private readonly Dictionary<string, (byte[] Wrapped, StoredKeyInfo Info)> _custody = [];

    public WrappingExternalKeyStore(byte[] wrappingKey) => _wrappingKey = wrappingKey;

    /// <summary>How many times a reader delegate of this store has been entered. Never above 1
    /// per import — the external-assembly counterpart of the library's internal read counter.</summary>
    public int ReaderEntries { get; private set; }

    public KeyStoreNamespaceId NamespaceId { get; } = new("external-test");

    public Task<KeyStoreCapabilitySet> GetCapabilitiesAsync(CancellationToken ct = default) =>
        Task.FromResult(new KeyStoreCapabilitySet(
            "r1", [new KeyStoreCapability(KeyType.Ed25519, KeyStoreOperation.Import, null, 256)]));

    /// <summary>
    /// The routed import. This method is the whole reason #28 exists: before the widening it
    /// could not be written outside the NetCrypto assembly at all.
    /// </summary>
    public Task<KeyMutationResult> ImportAsync(KeyImportRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // A replay must destroy the material WITHOUT reading it (FR-7b rule 7).
        if (_custody.ContainsKey(request.Alias))
        {
            request.Material.Discard();
            var replayed = _custody[request.Alias];
            return Task.FromResult(new KeyMutationResult(
                replayed.Info, replayed.Info.InstanceId!.Value, Replayed: true));
        }

        var instanceId = new KeyInstanceId($"inst-{request.Alias}");

        // The one sanctioned read. The delegate is this store's acceptance path; the material
        // latches unreadable on the way out whether or not the wrap below succeeds.
        KeyMaterialReader<(byte[] Wrapped, byte[] PublicKey, KeyType KeyType)> reader =
            (keyType, publicKey, privateKey) =>
            {
                ReaderEntries++;

                // FR-7b obligation 13: the public key a store publishes is the verification
                // identity downstream code trusts, so it is derived from the secret rather than
                // believed from the caller's copy. Doing it here, inside the one read, is the
                // only chance — the buffer is gone the moment this returns. That an out-of-
                // assembly store can satisfy this obligation entirely through public API is part
                // of what #28 had to make true.
                using var derived = Generator.FromPrivateKey(keyType, privateKey);
                if (!derived.PublicKey.AsSpan().SequenceEqual(publicKey))
                    throw new ArgumentException(
                        "The transferred public key does not belong to the transferred private key.",
                        nameof(request));

                return (Wrap(privateKey), derived.PublicKey, keyType);
            };

        var accepted = request.Material.Consume(reader);

        var info = new StoredKeyInfo
        {
            Alias = request.Alias,
            KeyType = accepted.KeyType,
            PublicKey = accepted.PublicKey,
            InstanceId = instanceId,
        };
        _custody[request.Alias] = (accepted.Wrapped, info);

        return Task.FromResult(new KeyMutationResult(info, instanceId, Replayed: false));
    }

    /// <summary>Unwraps what custody holds — the test's proof that the true secret crossed.</summary>
    public byte[] Unwrap(string alias) => Wrap(_custody[alias].Wrapped);

    private byte[] Wrap(ReadOnlySpan<byte> material)
    {
        var wrapped = new byte[material.Length];
        for (int i = 0; i < material.Length; i++)
            wrapped[i] = (byte)(material[i] ^ _wrappingKey[i % _wrappingKey.Length]);
        return wrapped;
    }

    // --- everything else is deliberately unimplemented; see the class remarks ---

    private static Task<T> NotThisStore<T>() =>
        throw new NotSupportedException("This store implements import only.");

    public Task<KeyMutationResult> GenerateAsync(KeyGenerateRequest request, CancellationToken ct = default) => NotThisStore<KeyMutationResult>();
    public Task<KeyDeleteResult> DeleteAsync(KeyDeleteRequest request, CancellationToken ct = default) => NotThisStore<KeyDeleteResult>();
    public Task<KeyMutationOutcome?> GetMutationOutcomeAsync(KeyMutationKind kind, KeyOperationId operationId, CancellationToken ct = default) => NotThisStore<KeyMutationOutcome?>();
    public Task<StoredKeyInfo?> GetInfoAsync(string alias, KeyInstanceId instanceId, CancellationToken ct = default) => NotThisStore<StoredKeyInfo?>();
    public Task<byte[]> SignAsync(KeySignRequest request, CancellationToken ct = default) => NotThisStore<byte[]>();
    public Task<byte[]> SignBbsAsync(KeyBbsSignRequest request, CancellationToken ct = default) => NotThisStore<byte[]>();
    public Task<byte[]> DeriveSharedSecretAsync(KeyAgreementRequest request, CancellationToken ct = default) => NotThisStore<byte[]>();

    public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default) => NotThisStore<StoredKeyInfo>();
    public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default) => NotThisStore<StoredKeyInfo>();
    public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default) => NotThisStore<StoredKeyInfo?>();
    public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default) => NotThisStore<byte[]>();
    public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default) => NotThisStore<ISigner>();
    public Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default) => NotThisStore<byte[]>();
    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<string>>([.. _custody.Keys]);
    public Task<bool> DeleteAsync(string alias, CancellationToken ct = default) => NotThisStore<bool>();
}
