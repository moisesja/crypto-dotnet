using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Codecs;

/// <summary>
/// Issue #12 (G4) — base64url (RFC 4648 §5, no padding), the JOSE/JWK byte-to-text boundary.
/// </summary>
public class Base64UrlTests
{
    [Fact]
    public void Encode_Empty_ReturnsEmptyString()
    {
        Base64Url.Encode(ReadOnlySpan<byte>.Empty).Should().BeEmpty();
    }

    [Fact]
    public void Decode_Empty_ReturnsEmptyArray()
    {
        Base64Url.Decode(ReadOnlySpan<char>.Empty).Should().BeEmpty();
    }

    [Fact]
    public void Encode_JoseVector_MatchesRfc7515AppendixA1()
    {
        // RFC 7515 Appendix A.1 — the JWS protected header octets and their base64url encoding.
        byte[] header =
        [
            123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108,
            103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125
        ];

        Base64Url.Encode(header).Should().Be("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");
    }

    [Fact]
    public void Decode_JoseVector_RecoversOctets()
    {
        var decoded = Base64Url.Decode("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

        decoded.Should().Equal(
            123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108,
            103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125);
    }

    [Fact]
    public void Encode_NeverEmitsPadding()
    {
        // 1- and 2-byte inputs are the cases standard base64 would pad with '=' / '=='.
        Base64Url.Encode(new byte[] { 0x01 }).Should().NotContain("=");
        Base64Url.Encode(new byte[] { 0x01, 0x02 }).Should().NotContain("=");
    }

    [Fact]
    public void Encode_UsesUrlSafeAlphabet()
    {
        // The two alphabet positions that differ from standard base64: index 62 ('-' not '+')
        // and index 63 ('_' not '/').
        Base64Url.Encode(new byte[] { 0xFB }).Should().Be("-w");          // first sextet 111110 = 62 = '-'
        Base64Url.Encode(new byte[] { 0xFF, 0xFF, 0xFF }).Should().Be("____"); // four sextets of 63 = '_'
    }

    [Fact]
    public void Decode_ToleratesTrailingPadding()
    {
        // "AQ" encodes the single byte 0x01; standard base64 would pad it to "AQ==". A producer that
        // emits padded base64url must still decode identically to the unpadded form.
        var unpadded = Base64Url.Decode("AQ");
        var padded = Base64Url.Decode("AQ==");

        unpadded.Should().Equal(0x01);
        padded.Should().Equal(unpadded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(64)]
    public void EncodeThenDecode_RoundTripsAnyLength(int length)
    {
        var data = RandomNumberGenerator.GetBytes(length);

        var roundTripped = Base64Url.Decode(Base64Url.Encode(data));

        roundTripped.Should().Equal(data);
    }

    [Fact]
    public void Decode_InvalidCharacter_Throws()
    {
        // '!' is outside the base64url alphabet.
        var act = () => Base64Url.Decode("not-valid-base64!!");
        act.Should().Throw<FormatException>();
    }
}
