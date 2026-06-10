using System.Text;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Hashing;

/// <summary>
/// FR-10 — SHA-2 hashing helpers (FIPS 180-4 known-answer tests).
/// </summary>
/// <remarks>
/// Vector sources:
/// <list type="bullet">
/// <item>"abc" digests: NIST FIPS 180-4 example values ("One Block Message Sample",
/// Input Message: "abc") published as the CSRC "Examples with Intermediate Values"
/// documents SHA256.pdf / SHA384.pdf / SHA512.pdf at
/// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values</item>
/// <item>Empty-input digests: NIST CAVP SHA byte test vectors (shabytetestvectors.zip),
/// files SHA256ShortMsg.rsp / SHA384ShortMsg.rsp / SHA512ShortMsg.rsp, entry "Len = 0".</item>
/// </list>
/// </remarks>
public class HashTests
{
    private static byte[] Abc => Encoding.ASCII.GetBytes("abc");

    // ----- FIPS 180-4 known answers: "abc" -----

    /// <summary>
    /// NIST FIPS 180-4 example values, SHA256.pdf "One Block Message Sample": SHA-256("abc").
    /// </summary>
    [Fact]
    public void Sha256_Abc_MatchesFips180_4KnownAnswer()
    {
        var expected = Convert.FromHexString(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        Hash.Sha256(Abc).Should().Equal(expected);
    }

    /// <summary>
    /// NIST FIPS 180-4 example values, SHA384.pdf "One Block Message Sample": SHA-384("abc").
    /// </summary>
    [Fact]
    public void Sha384_Abc_MatchesFips180_4KnownAnswer()
    {
        var expected = Convert.FromHexString(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163" +
            "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");

        Hash.Sha384(Abc).Should().Equal(expected);
    }

    /// <summary>
    /// NIST FIPS 180-4 example values, SHA512.pdf "One Block Message Sample": SHA-512("abc")
    /// ("Message Digest is DDAF35A1 93617ABA CC417349 AE204131 12E6FA4E 89A97EA2 0A9EEEE6
    /// 4B55D39A 2192992A 274FC1A8 36BA3C23 A3FEEBBD 454D4423 643CE80E 2A9AC94F A54CA49F").
    /// </summary>
    [Fact]
    public void Sha512_Abc_MatchesFips180_4KnownAnswer()
    {
        var expected = Convert.FromHexString(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

        Hash.Sha512(Abc).Should().Equal(expected);
    }

    // ----- Empty-input known answers -----

    /// <summary>
    /// NIST CAVP SHA256ShortMsg.rsp, "Len = 0": SHA-256 of the empty message.
    /// </summary>
    [Fact]
    public void Sha256_EmptyInput_MatchesKnownAnswer()
    {
        var expected = Convert.FromHexString(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        Hash.Sha256(ReadOnlySpan<byte>.Empty).Should().Equal(expected);
    }

    /// <summary>
    /// NIST CAVP SHA384ShortMsg.rsp, "Len = 0": SHA-384 of the empty message.
    /// </summary>
    [Fact]
    public void Sha384_EmptyInput_MatchesKnownAnswer()
    {
        var expected = Convert.FromHexString(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743" +
            "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");

        Hash.Sha384(ReadOnlySpan<byte>.Empty).Should().Equal(expected);
    }

    /// <summary>
    /// NIST CAVP SHA512ShortMsg.rsp, "Len = 0": SHA-512 of the empty message.
    /// </summary>
    [Fact]
    public void Sha512_EmptyInput_MatchesKnownAnswer()
    {
        var expected = Convert.FromHexString(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        Hash.Sha512(ReadOnlySpan<byte>.Empty).Should().Equal(expected);
    }

    // ----- Try* overloads: success path -----

    [Fact]
    public void TrySha256_ExactSizeDestination_WritesDigestAndReportsLength()
    {
        var destination = new byte[32];

        var success = Hash.TrySha256(Abc, destination, out var bytesWritten);

        success.Should().BeTrue();
        bytesWritten.Should().Be(32);
        destination.Should().Equal(Hash.Sha256(Abc));
    }

    [Fact]
    public void TrySha384_ExactSizeDestination_WritesDigestAndReportsLength()
    {
        var destination = new byte[48];

        var success = Hash.TrySha384(Abc, destination, out var bytesWritten);

        success.Should().BeTrue();
        bytesWritten.Should().Be(48);
        destination.Should().Equal(Hash.Sha384(Abc));
    }

    [Fact]
    public void TrySha512_ExactSizeDestination_WritesDigestAndReportsLength()
    {
        var destination = new byte[64];

        var success = Hash.TrySha512(Abc, destination, out var bytesWritten);

        success.Should().BeTrue();
        bytesWritten.Should().Be(64);
        destination.Should().Equal(Hash.Sha512(Abc));
    }

    [Fact]
    public void TrySha256_OversizedDestination_WritesDigestIntoPrefix()
    {
        var destination = new byte[40];

        var success = Hash.TrySha256(Abc, destination, out var bytesWritten);

        success.Should().BeTrue();
        bytesWritten.Should().Be(32);
        destination.AsSpan(0, 32).ToArray().Should().Equal(Hash.Sha256(Abc));
        destination.AsSpan(32).ToArray().Should().OnlyContain(b => b == 0);
    }

    // ----- Try* overloads: too-small destination -----

    [Fact]
    public void TrySha256_TooSmallDestination_ReturnsFalseAndWritesNothing()
    {
        var destination = new byte[31];

        var success = Hash.TrySha256(Abc, destination, out var bytesWritten);

        success.Should().BeFalse();
        bytesWritten.Should().Be(0);
        destination.Should().OnlyContain(b => b == 0);
    }

    [Fact]
    public void TrySha384_TooSmallDestination_ReturnsFalseAndWritesNothing()
    {
        var destination = new byte[47];

        var success = Hash.TrySha384(Abc, destination, out var bytesWritten);

        success.Should().BeFalse();
        bytesWritten.Should().Be(0);
        destination.Should().OnlyContain(b => b == 0);
    }

    [Fact]
    public void TrySha512_TooSmallDestination_ReturnsFalseAndWritesNothing()
    {
        var destination = new byte[63];

        var success = Hash.TrySha512(Abc, destination, out var bytesWritten);

        success.Should().BeFalse();
        bytesWritten.Should().Be(0);
        destination.Should().OnlyContain(b => b == 0);
    }
}
