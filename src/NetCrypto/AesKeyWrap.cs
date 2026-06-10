using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// AES Key Wrap with a 256-bit key-encryption key (RFC 3394 / NIST SP 800-38F, called
/// <c>A256KW</c> in RFC 7518 §4.4). Wraps key material (such as a JWE content-encryption
/// key) under a KEK so the recipient can recover it with the same KEK.
/// </summary>
/// <remarks>
/// <para>
/// .NET does not expose a public AES Key Wrap API. This implementation follows RFC 3394 §2.2:
/// six rounds of <c>(A, t = (n*j)+i) ↦ AES-ECB-encrypt(KEK, A ‖ R[i])</c>, splitting the
/// ciphertext into <c>A</c> (high 64 bits, XOR'd with <c>t</c>) and <c>R[i]</c> (low 64 bits).
/// <see cref="Unwrap"/> inverts the loop and verifies the recovered <c>A</c> equals the default
/// IV <c>A6A6A6A6A6A6A6A6</c> (RFC 3394 §2.2.3.1) via
/// <see cref="CryptographicOperations.FixedTimeEquals"/>.
/// </para>
/// <para>
/// The wrapped key is the key data plus 8 bytes (one extra semiblock of integrity material).
/// The key data MUST be a multiple of 8 bytes and at least 16 bytes (RFC 3394 §2 requires
/// n ≥ 2 semiblocks); A256KW in JOSE always wraps 16-, 24-, 32-, 48-, or 64-byte CEKs, so
/// this is satisfied in practice.
/// </para>
/// </remarks>
public static class AesKeyWrap
{
    private const int BlockSize = 8;
    private const int KekSize = 32; // A256KW: 256-bit KEK.
    private const int MinKeyDataSize = 16; // RFC 3394 §2: n >= 2 semiblocks.

    // RFC 3394 §2.2.3.1 default Initial Value.
    private static ReadOnlySpan<byte> DefaultIv => [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    /// <summary>Wraps <paramref name="keyData"/> under <paramref name="kek"/> per RFC 3394 §2.2.1.</summary>
    /// <param name="kek">The 256-bit key-encryption key.</param>
    /// <param name="keyData">The key material to wrap. Length MUST be a multiple of 8 and at
    /// least 16 bytes.</param>
    /// <returns>The wrapped key, <c>keyData.Length + 8</c> bytes.</returns>
    /// <exception cref="ArgumentException">If <paramref name="kek"/> is not 32 bytes, or
    /// <paramref name="keyData"/> is not a multiple of 8 bytes at least 16 bytes long.</exception>
    public static byte[] Wrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> keyData)
    {
        if (kek.Length != KekSize)
            throw new ArgumentException($"A256KW KEK must be {KekSize} bytes, got {kek.Length}.", nameof(kek));
        if (keyData.Length < MinKeyDataSize || keyData.Length % BlockSize != 0)
            throw new ArgumentException($"A256KW key data must be a multiple of {BlockSize} bytes and at least {MinKeyDataSize}, got {keyData.Length}.", nameof(keyData));

        var n = keyData.Length / BlockSize;

        // Initialize A = IV; R[1..n] = key data blocks (RFC 3394 §2.2.1 step 1).
        Span<byte> a = stackalloc byte[BlockSize];
        DefaultIv.CopyTo(a);

        var r = new byte[n * BlockSize];
        keyData.CopyTo(r);

        using var aes = CreateEcbCipher(kek);
        Span<byte> block = stackalloc byte[BlockSize * 2];
        Span<byte> encrypted = stackalloc byte[BlockSize * 2];

        // RFC 3394 §2.2.1 step 2: 6 * n rounds.
        for (var j = 0; j < 6; j++)
        {
            for (var i = 0; i < n; i++)
            {
                a.CopyTo(block);
                r.AsSpan(i * BlockSize, BlockSize).CopyTo(block[BlockSize..]);

                // B = AES(K, A ‖ R[i])
                aes.EncryptEcb(block, encrypted, PaddingMode.None);

                // A = MSB64(B) XOR t, where t = (n * j) + i + 1
                var t = (ulong)(n * j) + (ulong)i + 1UL;
                var aHigh = BinaryPrimitives.ReadUInt64BigEndian(encrypted[..BlockSize]) ^ t;
                BinaryPrimitives.WriteUInt64BigEndian(a, aHigh);

                // R[i] = LSB64(B)
                encrypted.Slice(BlockSize, BlockSize).CopyTo(r.AsSpan(i * BlockSize, BlockSize));
            }
        }

        var output = new byte[BlockSize + r.Length];
        a.CopyTo(output);
        r.AsSpan().CopyTo(output.AsSpan(BlockSize));
        return output;
    }

    /// <summary>Unwraps <paramref name="wrappedKey"/> under <paramref name="kek"/> per RFC 3394 §2.2.2
    /// and returns the original key data.</summary>
    /// <param name="kek">The 256-bit key-encryption key.</param>
    /// <param name="wrappedKey">The output of a prior <see cref="Wrap"/> call. Length MUST be a
    /// multiple of 8 and at least 24 bytes (16 bytes of key data plus the 8-byte integrity block).</param>
    /// <returns>The recovered key data, <c>wrappedKey.Length - 8</c> bytes.</returns>
    /// <exception cref="ArgumentException">If <paramref name="kek"/> is not 32 bytes, or
    /// <paramref name="wrappedKey"/> is not a multiple of 8 bytes at least 24 bytes long.</exception>
    /// <exception cref="CryptographicException">If the integrity check fails — the recovered
    /// <c>A</c> does not equal the default IV (RFC 3394 §2.2.3), compared in constant time.</exception>
    public static byte[] Unwrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrappedKey)
    {
        if (kek.Length != KekSize)
            throw new ArgumentException($"A256KW KEK must be {KekSize} bytes, got {kek.Length}.", nameof(kek));
        if (wrappedKey.Length < MinKeyDataSize + BlockSize || wrappedKey.Length % BlockSize != 0)
            throw new ArgumentException($"A256KW wrapped key must be a multiple of {BlockSize} bytes and at least {MinKeyDataSize + BlockSize}, got {wrappedKey.Length}.", nameof(wrappedKey));

        var n = (wrappedKey.Length / BlockSize) - 1;

        // Initialize A = C[0]; R[1..n] = C[1..n] (RFC 3394 §2.2.2 step 1).
        Span<byte> a = stackalloc byte[BlockSize];
        wrappedKey[..BlockSize].CopyTo(a);

        var r = new byte[n * BlockSize];
        wrappedKey.Slice(BlockSize, n * BlockSize).CopyTo(r);

        using var aes = CreateEcbCipher(kek);
        Span<byte> block = stackalloc byte[BlockSize * 2];
        Span<byte> decrypted = stackalloc byte[BlockSize * 2];

        // RFC 3394 §2.2.2 step 2: 6 * n rounds, reverse order.
        for (var j = 5; j >= 0; j--)
        {
            for (var i = n - 1; i >= 0; i--)
            {
                // B = AES-1(K, (A XOR t) ‖ R[i]), t = (n * j) + i + 1
                var t = (ulong)(n * j) + (ulong)i + 1UL;
                var aHigh = BinaryPrimitives.ReadUInt64BigEndian(a) ^ t;
                BinaryPrimitives.WriteUInt64BigEndian(block, aHigh);
                r.AsSpan(i * BlockSize, BlockSize).CopyTo(block[BlockSize..]);

                aes.DecryptEcb(block, decrypted, PaddingMode.None);

                // A = MSB64(B), R[i] = LSB64(B)
                decrypted[..BlockSize].CopyTo(a);
                decrypted.Slice(BlockSize, BlockSize).CopyTo(r.AsSpan(i * BlockSize, BlockSize));
            }
        }

        // Integrity check (RFC 3394 §2.2.3) — constant time.
        Span<byte> expectedIv = stackalloc byte[BlockSize];
        DefaultIv.CopyTo(expectedIv);
        if (!CryptographicOperations.FixedTimeEquals(a, expectedIv))
            throw new CryptographicException("A256KW unwrap integrity check failed (IV mismatch).");

        return r;
    }

    private static Aes CreateEcbCipher(ReadOnlySpan<byte> kek)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        var kekArray = kek.ToArray();
        aes.Key = kekArray;
        CryptographicOperations.ZeroMemory(kekArray);
        return aes;
    }
}
