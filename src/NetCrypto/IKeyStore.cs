namespace NetCrypto;

/// <summary>
/// Pluggable key storage abstraction. Private key material may never be extractable
/// (HSM-first design). NetDid generates keys via <see cref="IKeyGenerator"/> but does not store them.
/// </summary>
public interface IKeyStore
{
    /// <summary>
    /// Generate a new key pair inside the store. For HSM-backed stores, the private
    /// key is created within the secure enclave and never leaves it.
    /// </summary>
    Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default);

    /// <summary>Import an externally-generated key pair into the store.</summary>
    Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default);

    /// <summary>Get public key and metadata for a stored key. The private key is never exposed.</summary>
    Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default);

    /// <summary>Sign data using a stored key. The private key never leaves the store.</summary>
    Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default);

    /// <summary>Create an ISigner backed by this store for the given key alias.</summary>
    Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default);

    /// <summary>List all stored key aliases.</summary>
    Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default);

    /// <summary>Delete a key by alias.</summary>
    Task<bool> DeleteAsync(string alias, CancellationToken ct = default);
}
