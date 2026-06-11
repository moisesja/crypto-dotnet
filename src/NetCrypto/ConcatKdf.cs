using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// NIST SP 800-56A §5.8.1 Concat KDF with SHA-256, as bound by RFC 7518 §4.6.
/// </summary>
/// <remarks>
/// <para>
/// This is the canonical KDF for JOSE ECDH-ES (RFC 7518 §4.6) and ECDH-1PU
/// (draft-madden-jose-ecdh-1pu §2). Callers pair it with a raw shared secret produced by
/// <see cref="ICryptoProvider.DeriveSharedSecret"/>:
/// </para>
/// <code>
/// var z = crypto.DeriveSharedSecret(KeyType.X25519, alicePriv, bobPub);
/// var contentKey = ConcatKdf.DeriveKey(
///     sharedSecret: z,
///     algorithmId: Encoding.UTF8.GetBytes("A128GCM"),
///     partyUInfo:  Encoding.UTF8.GetBytes("Alice"),
///     partyVInfo:  Encoding.UTF8.GetBytes("Bob"),
///     suppPubInfo: [0x00, 0x00, 0x00, 0x80],  // 128 bits, BE
///     suppPrivInfo: ReadOnlySpan&lt;byte&gt;.Empty,
///     keyDataLen:  16);
/// </code>
/// <para>
/// For ECDH-1PU, pass <c>Ze ‖ Zs</c> (in that order) as <c>sharedSecret</c> and append the
/// AEAD authentication tag to <c>suppPubInfo</c> after the keydatalen bytes
/// (draft-madden-jose-ecdh-1pu §2.3).
/// </para>
/// </remarks>
public static class ConcatKdf
{
    private const int Sha256OutputLen = 32;

    /// <summary>
    /// Derive <paramref name="keyDataLen"/> bytes of keying material from
    /// <paramref name="sharedSecret"/> using the Concat KDF construction defined in
    /// NIST SP 800-56A §5.8.1 with SHA-256, exactly as bound by RFC 7518 §4.6.
    /// </summary>
    /// <param name="sharedSecret">The raw shared secret "Z". For ECDH-1PU pass
    /// <c>Ze ‖ Zs</c>.</param>
    /// <param name="algorithmId">PartyUInfo's <c>AlgorithmID</c>: the bytes of the JOSE
    /// <c>"enc"</c> or <c>"alg"</c> name (e.g. UTF-8 of <c>"A256KW"</c> or
    /// <c>"A256CBC-HS512"</c>), without length prefix — the 4-byte BE length is added internally.</param>
    /// <param name="partyUInfo">apu — sender info. Pass empty for absent. Length-prefixed internally.</param>
    /// <param name="partyVInfo">apv — receiver info. Pass empty for absent. Length-prefixed internally.</param>
    /// <param name="suppPubInfo">Per RFC 7518 §4.6.2, the keydatalen in bits as a 32-bit
    /// big-endian integer. For ECDH-1PU per draft-madden-jose-ecdh-1pu §2.3, append the AEAD
    /// authentication tag after that 4-byte field. Passed through verbatim — no length prefix added.</param>
    /// <param name="suppPrivInfo">Supplemental private info. Almost always empty for JOSE. Passed through verbatim.</param>
    /// <param name="keyDataLen">Desired output length in bytes (e.g. 16 for A128KW, 32 for A256GCM).</param>
    /// <returns><paramref name="keyDataLen"/> bytes of derived keying material.</returns>
    /// <exception cref="ArgumentOutOfRangeException">If <paramref name="keyDataLen"/> is non-positive
    /// or exceeds the maximum supported length.</exception>
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> partyUInfo,
        ReadOnlySpan<byte> partyVInfo,
        ReadOnlySpan<byte> suppPubInfo,
        ReadOnlySpan<byte> suppPrivInfo,
        int keyDataLen)
    {
        if (keyDataLen <= 0)
            throw new ArgumentOutOfRangeException(nameof(keyDataLen), "Must be greater than zero.");
        // SP 800-56A caps output at hashlen·(2³²−1); cap below int.MaxValue so the block-count
        // and buffer-size arithmetic below cannot overflow into an OverflowException (NFR-3).
        const int MaxKeyDataLen = int.MaxValue - Sha256OutputLen;
        if (keyDataLen > MaxKeyDataLen)
            throw new ArgumentOutOfRangeException(nameof(keyDataLen), $"Must not exceed {MaxKeyDataLen}.");

        // Spec: T_i = SHA-256(counter_i ‖ Z ‖ OtherInfo)
        // OtherInfo = lp(AlgorithmID) ‖ lp(PartyUInfo) ‖ lp(PartyVInfo) ‖ SuppPubInfo ‖ SuppPrivInfo
        // where lp(X) = (X.Length as 4-byte big-endian) ‖ X.
        //
        // Output = (T_1 ‖ T_2 ‖ ... ‖ T_n)[0..keyDataLen] where n = ceil(keyDataLen / 32).
        // Counter starts at 1 and increments by 1 for each block.

        var n = (keyDataLen + Sha256OutputLen - 1) / Sha256OutputLen;
        var output = new byte[n * Sha256OutputLen];

        Span<byte> lengthBuffer = stackalloc byte[4];
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        for (var i = 1; i <= n; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(lengthBuffer, (uint)i);
            hash.AppendData(lengthBuffer);

            hash.AppendData(sharedSecret);

            AppendLengthPrefixed(hash, algorithmId, lengthBuffer);
            AppendLengthPrefixed(hash, partyUInfo, lengthBuffer);
            AppendLengthPrefixed(hash, partyVInfo, lengthBuffer);

            hash.AppendData(suppPubInfo);
            hash.AppendData(suppPrivInfo);

            hash.GetHashAndReset(output.AsSpan((i - 1) * Sha256OutputLen, Sha256OutputLen));
        }

        if (keyDataLen == output.Length)
            return output;

        var truncated = new byte[keyDataLen];
        Buffer.BlockCopy(output, 0, truncated, 0, keyDataLen);
        return truncated;
    }

    private static void AppendLengthPrefixed(IncrementalHash hash, ReadOnlySpan<byte> data, Span<byte> lengthScratch)
    {
        BinaryPrimitives.WriteUInt32BigEndian(lengthScratch, (uint)data.Length);
        hash.AppendData(lengthScratch);
        if (data.Length > 0)
            hash.AppendData(data);
    }
}
