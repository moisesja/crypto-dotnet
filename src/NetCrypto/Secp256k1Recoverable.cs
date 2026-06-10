using System.Security.Cryptography;
using NBitcoin.Secp256k1;

namespace NetCrypto;

/// <summary>
/// Recoverable ECDSA over secp256k1 (FR-12): signs a caller-supplied 32-byte digest and
/// returns a 64-byte compact <c>R‖S</c> signature plus the recovery id needed to recover
/// the signing public key from the signature alone. Signatures are deterministic
/// (RFC 6979 nonces) and low-S normalized (<c>S ≤ n/2</c>). Backed by NBitcoin.Secp256k1.
/// </summary>
/// <remarks>
/// <para>
/// No hashing is performed here — callers supply the digest. For did:ethr / EVM flows
/// that digest is Keccak-256 of the signing payload, computed by the caller.
/// </para>
/// <para>
/// <b>Boundary (PRD FR-12 ruling):</b> NetCrypto returns the <i>raw</i> recovery id
/// (0–3) only. EVM <c>v</c>-encoding — legacy <c>27 + recid</c> or EIP-155
/// <c>35 + recid + 2·chainId</c> — is the wallet layer's responsibility and is
/// deliberately absent from this library.
/// </para>
/// </remarks>
public static class Secp256k1Recoverable
{
    private const int PrivateKeySizeBytes = 32;
    private const int DigestSizeBytes = 32;
    private const int SignatureSizeBytes = 64;
    private const int CompressedPublicKeySizeBytes = 33;
    private const int UncompressedPublicKeySizeBytes = 65;

    /// <summary>
    /// Signs a 32-byte digest with a secp256k1 private key, producing a recoverable
    /// ECDSA signature. The digest is signed as-is — no internal hashing is applied.
    /// Nonces are deterministic per RFC 6979 and the signature is low-S normalized,
    /// with the recovery id adjusted accordingly.
    /// </summary>
    /// <param name="privateKey">The raw 32-byte big-endian private scalar, in <c>[1, n-1]</c>.</param>
    /// <param name="digest32">The 32-byte digest to sign (e.g. a Keccak-256 hash computed by the caller).</param>
    /// <returns>The 64-byte compact signature (<c>R‖S</c>, each 32 bytes big-endian) and the
    /// raw recovery id in <c>{0, 1, 2, 3}</c>. No EVM <c>v</c>-encoding is applied — adding
    /// <c>27</c> or the EIP-155 chain-id offset is the wallet layer's job.</returns>
    /// <exception cref="ArgumentException">If <paramref name="privateKey"/> is not 32 bytes
    /// or is not a valid scalar in <c>[1, n-1]</c>, or <paramref name="digest32"/> is not 32 bytes.</exception>
    /// <exception cref="CryptographicException">If signing fails internally (not expected for valid inputs).</exception>
    public static (byte[] Signature64, int RecoveryId) Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> digest32)
    {
        if (privateKey.Length != PrivateKeySizeBytes)
            throw new ArgumentException($"secp256k1 private key must be {PrivateKeySizeBytes} bytes, got {privateKey.Length}.", nameof(privateKey));
        if (digest32.Length != DigestSizeBytes)
            throw new ArgumentException($"Digest must be {DigestSizeBytes} bytes, got {digest32.Length}.", nameof(digest32));

        if (!Context.Instance.TryCreateECPrivKey(privateKey, out var key) || key is null)
            throw new ArgumentException("Invalid secp256k1 private key: the scalar must be in [1, n-1].", nameof(privateKey));

        using (key)
        {
            if (!key.TrySignRecoverable(digest32, out var signature) || signature is null)
                throw new CryptographicException("secp256k1 recoverable signing failed.");

            Span<byte> compact = stackalloc byte[SignatureSizeBytes];
            signature.WriteToSpanCompact(compact, out var recoveryId);
            return (compact.ToArray(), recoveryId);
        }
    }

    /// <summary>
    /// Recovers the public key that produced a recoverable ECDSA signature over the
    /// given 32-byte digest.
    /// </summary>
    /// <param name="digest32">The 32-byte digest that was signed.</param>
    /// <param name="signature64">The 64-byte compact signature (<c>R‖S</c>) from <see cref="Sign"/>.</param>
    /// <param name="recoveryId">The raw recovery id in <c>{0, 1, 2, 3}</c> returned by
    /// <see cref="Sign"/>. Callers holding an EVM <c>v</c> value must convert it back to the
    /// raw id themselves (<c>v - 27</c>, or the EIP-155 inverse) — NetCrypto deliberately
    /// performs no <c>v</c>-encoding or decoding.</param>
    /// <param name="compressed"><c>true</c> for the 33-byte compressed SEC 1 encoding;
    /// <c>false</c> (default) for the 65-byte uncompressed encoding with <c>0x04</c> prefix.</param>
    /// <returns>The recovered public key, 33 or 65 bytes per <paramref name="compressed"/>.</returns>
    /// <exception cref="ArgumentException">If <paramref name="digest32"/> is not 32 bytes,
    /// or <paramref name="signature64"/> is not 64 bytes or does not encode canonical
    /// scalars in <c>[1, n-1]</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">If <paramref name="recoveryId"/> is outside <c>0..3</c>.</exception>
    /// <exception cref="CryptographicException">If no public key can be recovered for the
    /// given digest, signature, and recovery id.</exception>
    public static byte[] RecoverPublicKey(ReadOnlySpan<byte> digest32, ReadOnlySpan<byte> signature64, int recoveryId, bool compressed = false)
    {
        if (digest32.Length != DigestSizeBytes)
            throw new ArgumentException($"Digest must be {DigestSizeBytes} bytes, got {digest32.Length}.", nameof(digest32));
        if (signature64.Length != SignatureSizeBytes)
            throw new ArgumentException($"Compact signature must be {SignatureSizeBytes} bytes, got {signature64.Length}.", nameof(signature64));
        if (recoveryId is < 0 or > 3)
            throw new ArgumentOutOfRangeException(nameof(recoveryId), recoveryId, "Recovery id must be 0, 1, 2, or 3.");

        // No valid ECDSA signature has R = 0 or S = 0; NBitcoin's compact parser only
        // rejects overflow (>= n), so reject zero scalars explicitly.
        if (signature64[..32].IndexOfAnyExcept((byte)0) < 0 || signature64[32..].IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Invalid compact signature: R and S must be canonical scalars in [1, n-1].", nameof(signature64));

        if (!SecpRecoverableECDSASignature.TryCreateFromCompact(signature64, recoveryId, out var signature) || signature is null)
            throw new ArgumentException("Invalid compact signature: R and S must be canonical scalars in [1, n-1].", nameof(signature64));

        if (!ECPubKey.TryRecover(Context.Instance, signature, digest32, out var publicKey) || publicKey is null)
            throw new CryptographicException("secp256k1 public key recovery failed for the given digest, signature, and recovery id.");

        var output = new byte[compressed ? CompressedPublicKeySizeBytes : UncompressedPublicKeySizeBytes];
        publicKey.WriteToSpan(compressed, output, out _);
        return output;
    }
}
