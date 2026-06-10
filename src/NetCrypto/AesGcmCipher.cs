using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// AES-256-GCM AEAD (JOSE <c>A256GCM</c>, RFC 7518 §5.3): 32-byte key, 12-byte nonce,
/// 16-byte authentication tag.
/// </summary>
/// <remarks>
/// Thin pass-through to the BCL <see cref="AesGcm"/>, which performs the constant-time tag
/// check internally and raises <see cref="AuthenticationTagMismatchException"/> on failure;
/// <see cref="Decrypt"/> surfaces the standard <see cref="CryptographicException"/> for
/// parity with the other AEADs.
/// </remarks>
public static class AesGcmCipher
{
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with AES-256-GCM.
    /// </summary>
    /// <param name="key">The 32-byte AES-256 key.</param>
    /// <param name="nonce">The 12-byte (96-bit) nonce. Must never be reused with the same
    /// key.</param>
    /// <param name="plaintext">The plaintext to encrypt. May be empty.</param>
    /// <param name="associatedData">Optional additional authenticated data covered by the
    /// authentication tag but not encrypted. Pass empty (the default) for none.</param>
    /// <returns>The ciphertext (same length as the plaintext) and the 16-byte
    /// authentication tag.</returns>
    /// <exception cref="ArgumentException">If <paramref name="key"/> is not 32 bytes or
    /// <paramref name="nonce"/> is not 12 bytes.</exception>
    public static (byte[] Ciphertext, byte[] Tag) Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ValidateKeyAndNonce(key, nonce);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSizeBytes];

        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return (ciphertext, tag);
    }

    /// <summary>
    /// Verifies the authentication tag and decrypts <paramref name="ciphertext"/> with
    /// AES-256-GCM.
    /// </summary>
    /// <param name="key">The 32-byte AES-256 key used at encryption.</param>
    /// <param name="nonce">The 12-byte (96-bit) nonce used at encryption.</param>
    /// <param name="ciphertext">The ciphertext produced by <see cref="Encrypt"/>.</param>
    /// <param name="tag">The 16-byte authentication tag produced by <see cref="Encrypt"/>.</param>
    /// <param name="associatedData">The additional authenticated data supplied at
    /// encryption. Pass empty (the default) for none.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="ArgumentException">If <paramref name="key"/> is not 32 bytes,
    /// <paramref name="nonce"/> is not 12 bytes, or <paramref name="tag"/> is not
    /// 16 bytes.</exception>
    /// <exception cref="CryptographicException">If authentication-tag verification fails
    /// (the key, nonce, ciphertext, tag, or associated data does not match what was
    /// authenticated at encryption).</exception>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ValidateKeyAndNonce(key, nonce);
        if (tag.Length != TagSizeBytes)
            throw new ArgumentException($"A256GCM tag must be {TagSizeBytes} bytes, got {tag.Length}.", nameof(tag));

        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, TagSizeBytes);
        try
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new CryptographicException("A256GCM authentication tag verification failed.");
        }

        return plaintext;
    }

    private static void ValidateKeyAndNonce(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"A256GCM key must be {KeySizeBytes} bytes, got {key.Length}.", nameof(key));
        if (nonce.Length != NonceSizeBytes)
            throw new ArgumentException($"A256GCM nonce must be {NonceSizeBytes} bytes, got {nonce.Length}.", nameof(nonce));
    }
}
