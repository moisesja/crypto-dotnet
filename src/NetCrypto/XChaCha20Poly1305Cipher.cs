using System.Security.Cryptography;
using NSec.Cryptography;

namespace NetCrypto;

/// <summary>
/// XChaCha20-Poly1305 AEAD (JOSE <c>XC20P</c>) per draft-irtf-cfrg-xchacha-03: a 32-byte key,
/// a 24-byte nonce, and a 16-byte Poly1305 authentication tag. XChaCha20 extends ChaCha20
/// (RFC 8439) with an HChaCha20 subkey derivation step so the nonce is large enough to be
/// chosen at random without practical collision risk.
/// </summary>
/// <remarks>
/// Thin pass-through to NSec's <see cref="AeadAlgorithm.XChaCha20Poly1305"/> (libsodium).
/// NSec emits and consumes a single combined buffer of <c>ciphertext ‖ tag</c>; this class
/// splits and recombines that buffer so the (ciphertext, tag) contract stays uniform with the
/// other NetCrypto AEADs.
/// </remarks>
public static class XChaCha20Poly1305Cipher
{
    /// <summary>Key size in bytes for XChaCha20-Poly1305 (<c>XC20P</c>): 32.</summary>
    public const int KeySizeBytes = 32;

    /// <summary>Nonce size in bytes for XChaCha20-Poly1305: 24 (the extended nonce, safe to choose at random).</summary>
    public const int NonceSizeBytes = 24;

    /// <summary>Poly1305 authentication-tag size in bytes for XChaCha20-Poly1305: 16.</summary>
    public const int TagSizeBytes = 16;

    private static readonly AeadAlgorithm Algorithm = AeadAlgorithm.XChaCha20Poly1305;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with XChaCha20-Poly1305 (JOSE <c>XC20P</c>,
    /// draft-irtf-cfrg-xchacha-03 §2.1).
    /// </summary>
    /// <param name="key">The 32-byte symmetric key.</param>
    /// <param name="nonce">The 24-byte nonce. Must be unique per (key, message); the extended
    /// nonce is the point of XChaCha20 — it is safe to generate at random.</param>
    /// <param name="plaintext">The plaintext to encrypt. May be empty.</param>
    /// <param name="associatedData">Optional additional authenticated data covered by the
    /// authentication tag but not encrypted. Pass empty (the default) for none.</param>
    /// <returns>The ciphertext (same length as <paramref name="plaintext"/>) and the 16-byte
    /// Poly1305 authentication tag.</returns>
    /// <exception cref="ArgumentException">If <paramref name="key"/> is not 32 bytes or
    /// <paramref name="nonce"/> is not 24 bytes.</exception>
    public static (byte[] Ciphertext, byte[] Tag) Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ValidateKeyAndNonce(key, nonce);

        using var nsecKey = Key.Import(Algorithm, key, KeyBlobFormat.RawSymmetricKey);
        var combined = Algorithm.Encrypt(nsecKey, nonce, associatedData, plaintext);

        // NSec returns [ciphertext ‖ tag]; split into the two pieces of the uniform AEAD contract.
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];
        combined.AsSpan(0, ciphertext.Length).CopyTo(ciphertext);
        combined.AsSpan(ciphertext.Length, TagSizeBytes).CopyTo(tag);

        return (ciphertext, tag);
    }

    /// <summary>
    /// Verifies the authentication tag and decrypts <paramref name="ciphertext"/> with
    /// XChaCha20-Poly1305 (JOSE <c>XC20P</c>, draft-irtf-cfrg-xchacha-03 §2.1).
    /// </summary>
    /// <param name="key">The 32-byte symmetric key used at encryption.</param>
    /// <param name="nonce">The 24-byte nonce used at encryption.</param>
    /// <param name="ciphertext">The ciphertext produced by <see cref="Encrypt"/>.</param>
    /// <param name="tag">The 16-byte Poly1305 authentication tag produced by <see cref="Encrypt"/>.</param>
    /// <param name="associatedData">The additional authenticated data supplied at encryption.
    /// Pass empty (the default) for none.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="ArgumentException">If <paramref name="key"/> is not 32 bytes,
    /// <paramref name="nonce"/> is not 24 bytes, or <paramref name="tag"/> is not 16 bytes.</exception>
    /// <exception cref="CryptographicException">If authentication fails — any modification of
    /// the ciphertext, tag, or associated data is rejected and no plaintext is returned.</exception>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ValidateKeyAndNonce(key, nonce);
        if (tag.Length != TagSizeBytes)
            throw new ArgumentException($"XC20P tag must be {TagSizeBytes} bytes, got {tag.Length}.", nameof(tag));

        using var nsecKey = Key.Import(Algorithm, key, KeyBlobFormat.RawSymmetricKey);

        // Re-combine [ciphertext ‖ tag] for NSec's decrypt contract.
        var combined = new byte[ciphertext.Length + TagSizeBytes];
        ciphertext.CopyTo(combined);
        tag.CopyTo(combined.AsSpan(ciphertext.Length));

        return Algorithm.Decrypt(nsecKey, nonce, associatedData, combined)
            ?? throw new CryptographicException("XC20P authentication tag verification failed.");
    }

    private static void ValidateKeyAndNonce(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"XC20P key must be {KeySizeBytes} bytes, got {key.Length}.", nameof(key));
        if (nonce.Length != NonceSizeBytes)
            throw new ArgumentException($"XC20P nonce must be {NonceSizeBytes} bytes, got {nonce.Length}.", nameof(nonce));
    }
}
