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

    /// <summary>
    /// Perform ECDH key agreement using a stored key-agreement private key and return the raw
    /// shared secret "Z". The private scalar never leaves the store — for an HSM- or keychain-backed
    /// store the agreement runs inside the secure boundary, so a non-extractable key can still
    /// participate in ECDH-based decryption (JOSE <c>ECDH-ES</c>/<c>ECDH-1PU</c>, DIDComm
    /// anoncrypt/authcrypt). This is the key-agreement counterpart to <see cref="SignAsync"/>.
    /// </summary>
    /// <param name="alias">Alias of the stored key. Must be an ECDH-capable type: X25519, P-256, P-384, or P-521.</param>
    /// <param name="peerPublicKey">The peer's public key in the canonical encoding for the stored key's curve:
    /// raw 32 bytes for X25519; SEC1 compressed (0x02/0x03 || X) or uncompressed (0x04 || X || Y) for the NIST curves.</param>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>The raw ECDH shared secret "Z" — no KDF, truncation, or normalization is applied, byte-for-byte
    /// identical to what <see cref="ICryptoProvider.DeriveSharedSecret"/> computes for the extractable equivalent.
    /// Apply a NIST SP 800-56A-conformant KDF (Concat KDF, HKDF, KMAC) before using it as keying material.</returns>
    /// <exception cref="KeyNotFoundException">No key is stored under <paramref name="alias"/>.</exception>
    /// <exception cref="ArgumentException">The stored key's type is not ECDH-capable, or <paramref name="peerPublicKey"/> is malformed for the curve.</exception>
    Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default);

    /// <summary>List all stored key aliases.</summary>
    Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default);

    /// <summary>Delete a key by alias.</summary>
    Task<bool> DeleteAsync(string alias, CancellationToken ct = default);
}
