namespace NetCrypto;

/// <summary>
/// Signs a caller-supplied 32-byte digest with a recoverable ECDSA signature, without the
/// private key necessarily being extractable — the recoverable counterpart to
/// <see cref="ISigner"/>, abstracting over <see cref="Secp256k1Recoverable.Sign"/> so that
/// HSM/key-store-held keys can produce EVM signatures too. The digest is signed as-is: no
/// hashing is applied by the implementation. In this library the capability is secp256k1-only
/// (Ed25519 and BLS signatures have no recovery-id concept).
/// </summary>
/// <remarks>
/// <b>Boundary (PRD FR-12 ruling):</b> implementations return the <i>raw</i> recovery id
/// (0–3) only. EVM <c>v</c>-encoding — legacy <c>27 + recid</c> or EIP-155
/// <c>35 + recid + 2·chainId</c> — and the Keccak-256 digest computation itself are the
/// wallet layer's responsibility and are deliberately absent from this library.
/// </remarks>
public interface IRecoverableDigestSigner
{
    /// <summary>The type of the key backing this signer.</summary>
    KeyType KeyType { get; }

    /// <summary>The public key bytes (always available, even for HSM-backed signers).</summary>
    ReadOnlyMemory<byte> PublicKey { get; }

    /// <summary>
    /// Signs a caller-supplied 32-byte digest as-is (no internal hashing; for EVM flows the
    /// caller computes the Keccak-256 digest). For HSM-backed signers, this delegates to the
    /// secure enclave without the private key ever leaving the device. The digest content is
    /// opaque to the signer — no semantic validation is performed (an all-zero digest is a
    /// valid ECDSA input); only its length is checked.
    /// </summary>
    /// <param name="digest32">The 32-byte digest to sign (e.g. a Keccak-256 hash computed by the caller).</param>
    /// <param name="ct">A token to cancel the operation.</param>
    /// <returns>The compact signature and raw recovery id. Signatures are deterministic
    /// (RFC 6979) and low-S normalized, matching <see cref="Secp256k1Recoverable.Sign"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="digest32"/> is not 32 bytes.</exception>
    /// <exception cref="NotSupportedException">The backing key's type does not support
    /// recoverable ECDSA (non-secp256k1 in this library).</exception>
    Task<RecoverableSignature> SignDigestAsync(ReadOnlyMemory<byte> digest32, CancellationToken ct = default);
}
