using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Encryption;

/// <summary>
/// FR-15 — <see cref="AesKeyWrap"/> (JOSE <c>A256KW</c>, RFC 3394) validated against the
/// RFC 3394 §4.3 and §4.6 known-answer vectors, seeded-random round-trips for every valid
/// CEK size, exhaustive single-bit tamper rejection, and the input-validation contract.
/// Vectors: https://www.rfc-editor.org/rfc/rfc3394.txt
/// </summary>
public class AesKeyWrapTests
{
    // ── RFC 3394 §4.6 — "Wrap 256 bits of Key Data with a 256-bit KEK", verbatim ──

    // RFC 3394 §4.6: KEK (256 bits).
    private static readonly byte[] Kek = RfcHex(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

    // RFC 3394 §4.6: Key Data (256 bits).
    private static readonly byte[] KeyData_4_6 = RfcHex(
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");

    // RFC 3394 §4.6: Ciphertext (320 bits).
    private static readonly byte[] Wrapped_4_6 = RfcHex(@"
        28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326
        CBC7F0E71A99F43B FB988B9B7A02DD21");

    // ── RFC 3394 §4.3 — "Wrap 128 bits of Key Data with a 256-bit KEK", verbatim ──
    // (§4.3 uses the same 256-bit KEK as §4.6.)

    // RFC 3394 §4.3: Key Data (128 bits).
    private static readonly byte[] KeyData_4_3 = RfcHex("00112233445566778899AABBCCDDEEFF");

    // RFC 3394 §4.3: Ciphertext (192 bits).
    private static readonly byte[] Wrapped_4_3 = RfcHex(
        "64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7");

    [Fact]
    public void Wrap_Rfc3394Section4_6_MatchesExpectedCiphertext()
    {
        var wrapped = AesKeyWrap.Wrap(Kek, KeyData_4_6);

        wrapped.Should().Equal(Wrapped_4_6,
            because: "RFC 3394 §4.6 publishes the exact wrapped output for 256-bit key data under a 256-bit KEK");
    }

    [Fact]
    public void Unwrap_Rfc3394Section4_6_RecoversKeyData()
    {
        var recovered = AesKeyWrap.Unwrap(Kek, Wrapped_4_6);

        recovered.Should().Equal(KeyData_4_6);
    }

    [Fact]
    public void Wrap_Rfc3394Section4_3_MatchesExpectedCiphertext()
    {
        var wrapped = AesKeyWrap.Wrap(Kek, KeyData_4_3);

        wrapped.Should().Equal(Wrapped_4_3,
            because: "RFC 3394 §4.3 publishes the exact wrapped output for 128-bit key data under a 256-bit KEK");
    }

    [Fact]
    public void Unwrap_Rfc3394Section4_3_RecoversKeyData()
    {
        var recovered = AesKeyWrap.Unwrap(Kek, Wrapped_4_3);

        recovered.Should().Equal(KeyData_4_3);
    }

    // ── FR-15 AC 2 — round-trip with random KEK/key data (sizes 16/24/32) is identity ──

    [Theory]
    [InlineData(16)]  // 128-bit CEK
    [InlineData(24)]  // 192-bit CEK
    [InlineData(32)]  // 256-bit CEK
    public void WrapThenUnwrap_SeededRandomKekAndKeyData_IsIdentity(int keyDataLength)
    {
        // Seeded so failures reproduce deterministically.
        var random = new Random(42 + keyDataLength);
        var kek = new byte[32];
        random.NextBytes(kek);
        var keyData = new byte[keyDataLength];
        random.NextBytes(keyData);

        var wrapped = AesKeyWrap.Wrap(kek, keyData);
        wrapped.Length.Should().Be(keyDataLength + 8,
            because: "RFC 3394 prepends 8 bytes of integrity material to the key data");

        var recovered = AesKeyWrap.Unwrap(kek, wrapped);
        recovered.Should().Equal(keyData);
    }

    // ── FR-15 AC 3 — any single-bit corruption of the wrapped output must throw ──

    [Fact]
    public void Unwrap_SingleBitFlipAtEveryBytePosition_ThrowsCryptographicException()
    {
        var random = new Random(1337);
        var kek = new byte[32];
        random.NextBytes(kek);
        var keyData = new byte[24];
        random.NextBytes(keyData);

        var wrapped = AesKeyWrap.Wrap(kek, keyData); // 32 bytes

        for (var index = 0; index < wrapped.Length; index++)
        {
            var tampered = (byte[])wrapped.Clone();
            tampered[index] ^= 0x01;

            var act = () => AesKeyWrap.Unwrap(kek, tampered);

            act.Should().Throw<CryptographicException>(
                because: $"RFC 3394 §2.2.3 mandates rejecting wrapped keys whose recovered IV differs from A6A6A6A6A6A6A6A6 (bit flipped at byte {index})");
        }
    }

    [Fact]
    public void Unwrap_WrongKek_ThrowsCryptographicException()
    {
        var wrongKek = (byte[])Kek.Clone();
        wrongKek[0] ^= 0x01;

        var act = () => AesKeyWrap.Unwrap(wrongKek, Wrapped_4_6);

        act.Should().Throw<CryptographicException>();
    }

    // ── Input validation (NFR-3): wrong sizes → ArgumentException with parameter name ──

    [Theory]
    [InlineData(0)]   // empty
    [InlineData(8)]   // single semiblock — below the RFC 3394 §2 minimum of n >= 2
    [InlineData(7)]   // not a multiple of 8
    [InlineData(15)]  // not a multiple of 8
    [InlineData(33)]  // not a multiple of 8
    public void Wrap_InvalidKeyDataLength_ThrowsArgumentException(int keyDataLength)
    {
        var act = () => AesKeyWrap.Wrap(new byte[32], new byte[keyDataLength]);

        act.Should().Throw<ArgumentException>().WithParameterName("keyData");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]  // A128KW KEK size — wrong for A256KW
    [InlineData(24)]  // A192KW KEK size — wrong for A256KW
    [InlineData(48)]
    public void Wrap_WrongKekLength_ThrowsArgumentException(int kekLength)
    {
        var act = () => AesKeyWrap.Wrap(new byte[kekLength], new byte[16]);

        act.Should().Throw<ArgumentException>().WithParameterName("kek");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(48)]
    public void Unwrap_WrongKekLength_ThrowsArgumentException(int kekLength)
    {
        var act = () => AesKeyWrap.Unwrap(new byte[kekLength], new byte[24]);

        act.Should().Throw<ArgumentException>().WithParameterName("kek");
    }

    [Theory]
    [InlineData(0)]   // empty
    [InlineData(8)]   // only the integrity block, no key data
    [InlineData(16)]  // would unwrap to 8 bytes — below the 16-byte key-data minimum
    [InlineData(23)]  // not a multiple of 8
    public void Unwrap_InvalidWrappedKeyLength_ThrowsArgumentException(int wrappedLength)
    {
        var act = () => AesKeyWrap.Unwrap(new byte[32], new byte[wrappedLength]);

        act.Should().Throw<ArgumentException>().WithParameterName("wrappedKey");
    }

    /// <summary>
    /// Decodes hex transcribed verbatim from the RFC (space- and newline-separated octet
    /// groups, exactly as printed) so the constants can be diffed against the source text.
    /// </summary>
    private static byte[] RfcHex(string hex) =>
        Convert.FromHexString(string.Concat(hex.Where(c => !char.IsWhiteSpace(c))));
}
