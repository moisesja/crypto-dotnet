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

    /// <summary>
    /// Signs a caller-supplied 32-byte digest with a stored secp256k1 key, producing a
    /// recoverable ECDSA signature (compact <c>R‖S</c> plus the raw recovery id). The digest is
    /// signed as-is — no hashing is applied — and the private key never leaves the store; this is
    /// the recoverable counterpart to <see cref="SignAsync"/>, enabling EVM flows (did:ethr,
    /// EIP-155 transactions) against HSM/vault-held keys. Per the PRD FR-12 boundary, no EVM
    /// <c>v</c>-encoding is applied — the raw recovery id (0–3) is returned.
    /// </summary>
    /// <remarks>
    /// The default implementation throws <see cref="NotSupportedException"/>, so existing store
    /// implementations stay source- and binary-compatible; stores opt in by overriding it.
    /// </remarks>
    /// <param name="alias">Alias of the stored key. Must be a secp256k1 key.</param>
    /// <param name="digest32">The 32-byte digest to sign (e.g. a Keccak-256 hash computed by the
    /// caller). Content is opaque — only the length is validated.</param>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>The compact signature and raw recovery id, deterministic (RFC 6979) and low-S
    /// normalized, matching <see cref="Secp256k1Recoverable.Sign"/>.</returns>
    /// <exception cref="KeyNotFoundException">No key is stored under <paramref name="alias"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="digest32"/> is not 32 bytes.</exception>
    /// <exception cref="NotSupportedException">The store does not support recoverable digest
    /// signing, or the stored key is not secp256k1.</exception>
    Task<RecoverableSignature> SignDigestAsync(string alias, ReadOnlyMemory<byte> digest32, CancellationToken ct = default)
    {
        // Validate the caller's argument before reporting the operation unsupported, so a malformed
        // digest surfaces as the same parameter-named ArgumentException the contract promises at
        // every entry point (an overriding store validates the same way).
        if (digest32.Length != 32)
            throw new ArgumentException($"Digest must be 32 bytes, got {digest32.Length}.", nameof(digest32));
        throw new NotSupportedException(
            "This key store does not support recoverable digest signing. Override SignDigestAsync to enable EVM flows.");
    }

    /// <summary>List all stored key aliases.</summary>
    Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default);

    /// <summary>Delete a key by alias.</summary>
    Task<bool> DeleteAsync(string alias, CancellationToken ct = default);
}
