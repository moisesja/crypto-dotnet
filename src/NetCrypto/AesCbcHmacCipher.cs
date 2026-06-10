using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// AES-256-CBC + HMAC-SHA-512 composite AEAD (JOSE <c>A256CBC-HS512</c>) exactly per
/// RFC 7518 §5.2.2: the 64-byte key is split into <c>MAC_KEY</c> (first 32 bytes) and
/// <c>ENC_KEY</c> (last 32 bytes), the plaintext is encrypted with AES-256-CBC (PKCS#7
/// padding, 16-byte IV), and the 32-byte authentication tag is the first half of
/// <c>HMAC-SHA-512(MAC_KEY, AAD ‖ IV ‖ ciphertext ‖ AL)</c>, where <c>AL</c> is the
/// bit-length of the additional authenticated data as a 64-bit big-endian integer.
/// </summary>
/// <remarks>
/// Encrypt-then-MAC: <see cref="Decrypt"/> verifies the tag in constant time
/// (<see cref="CryptographicOperations.FixedTimeEquals"/>) <b>before</b> any CBC
/// decryption runs, so tampered inputs are rejected without exposing a padding oracle.
/// </remarks>
public static class AesCbcHmacCipher
{
    private const int KeySizeBytes = 64;
    private const int IvSizeBytes = 16;
    private const int TagSizeBytes = 32;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> per RFC 7518 §5.2.2.1 (A256CBC-HS512).
    /// </summary>
    /// <param name="key">The 64-byte key: <c>MAC_KEY</c> = first 32 bytes,
    /// <c>ENC_KEY</c> = last 32 bytes (RFC 7518 §5.2.2.1 steps 1–2).</param>
    /// <param name="iv">The 16-byte AES-CBC initialization vector.</param>
    /// <param name="plaintext">The plaintext to encrypt. May be empty.</param>
    /// <param name="associatedData">Optional additional authenticated data covered by the
    /// authentication tag but not encrypted. Pass empty (the default) for none.</param>
    /// <returns>The PKCS#7-padded AES-256-CBC ciphertext and the 32-byte authentication
    /// tag (the first half of the HMAC-SHA-512 output).</returns>
    /// <exception cref="ArgumentException">If <paramref name="key"/> is not 64 bytes or
    /// <paramref name="iv"/> is not 16 bytes.</exception>
    public static (byte[] Ciphertext, byte[] Tag) Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        ValidateKeyAndIv(key, iv);

        var macKey = key[..32];
        var encKey = key.Slice(32, 32);

        byte[] ciphertext;
        var encKeyArray = encKey.ToArray();
        try
        {
            using var aes = Aes.Create();
            aes.Key = encKeyArray;
            ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encKeyArray);
        }

        var tag = ComputeTag(macKey, associatedData, iv, ciphertext);

        return (ciphertext, tag);
    }

    /// <summary>
    /// Verifies the authentication tag and, only on success, decrypts
    /// <paramref name="ciphertext"/> per RFC 7518 §5.2.2.2 (A256CBC-HS512).
    /// </summary>
    /// <param name="key">The 64-byte key: <c>MAC_KEY</c> = first 32 bytes,
    /// <c>ENC_KEY</c> = last 32 bytes (RFC 7518 §5.2.2.1 steps 1–2).</param>
    /// <param name="iv">The 16-byte AES-CBC initialization vector used at encryption.</param>
    /// <param name="ciphertext">The ciphertext produced by <see cref="Encrypt"/>.</param>
    /// <param name="tag">The 32-byte authentication tag produced by <see cref="Encrypt"/>.</param>
    /// <param name="associatedData">The additional authenticated data supplied at
    /// encryption. Pass empty (the default) for none.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="ArgumentException">If <paramref name="key"/> is not 64 bytes,
    /// <paramref name="iv"/> is not 16 bytes, or <paramref name="tag"/> is not 32 bytes.</exception>
    /// <exception cref="CryptographicException">If tag verification fails — thrown in
    /// constant time <b>before</b> any CBC decryption is attempted (no padding-oracle
    /// path).</exception>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        ValidateKeyAndIv(key, iv);
        if (tag.Length != TagSizeBytes)
            throw new ArgumentException($"A256CBC-HS512 tag must be {TagSizeBytes} bytes, got {tag.Length}.", nameof(tag));

        var macKey = key[..32];
        var encKey = key.Slice(32, 32);

        // FR-14 / RFC 7518 §5.2.2.2: verify the tag FIRST (encrypt-then-MAC). A tampered
        // input must be rejected before any CBC decryption work runs — no padding oracle.
        var expectedTag = ComputeTag(macKey, associatedData, iv, ciphertext);
        if (!CryptographicOperations.FixedTimeEquals(expectedTag, tag))
            throw new CryptographicException("A256CBC-HS512 authentication tag verification failed.");

        var encKeyArray = encKey.ToArray();
        try
        {
            using var aes = Aes.Create();
            aes.Key = encKeyArray;
            return aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encKeyArray);
        }
    }

    /// <summary>
    /// HMAC-SHA-512 over <c>AAD ‖ IV ‖ ciphertext ‖ AL</c> per RFC 7518 §5.2.2.1,
    /// returning the leftmost <see cref="TagSizeBytes"/> bytes. <c>AL</c> is the
    /// bit-length of the AAD as a 64-bit big-endian unsigned integer.
    /// </summary>
    private static byte[] ComputeTag(
        ReadOnlySpan<byte> macKey,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> ciphertext)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA512, macKey);
        hmac.AppendData(associatedData);
        hmac.AppendData(iv);
        hmac.AppendData(ciphertext);

        // RFC 7518 §5.2.2.1 step 4: AL = octets of the AAD length in BITS, big-endian, 64-bit.
        Span<byte> al = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(al, (ulong)associatedData.Length * 8);
        hmac.AppendData(al);

        Span<byte> fullMac = stackalloc byte[64];
        hmac.GetHashAndReset(fullMac);

        return fullMac[..TagSizeBytes].ToArray();
    }

    private static void ValidateKeyAndIv(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KeySizeBytes)
            throw new ArgumentException($"A256CBC-HS512 key must be {KeySizeBytes} bytes, got {key.Length}.", nameof(key));
        if (iv.Length != IvSizeBytes)
            throw new ArgumentException($"A256CBC-HS512 IV must be {IvSizeBytes} bytes, got {iv.Length}.", nameof(iv));
    }
}
