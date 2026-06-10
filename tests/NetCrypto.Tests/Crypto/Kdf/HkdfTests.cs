using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto.Kdf;

/// <summary>
/// FR-4 — <see cref="Hkdf"/> (RFC 5869 HMAC-based Extract-and-Expand KDF) validated
/// against the RFC 5869 Appendix A test vectors and the input-validation contract
/// (unsupported hash algorithm, non-positive / over-limit output length).
/// Vectors: https://www.rfc-editor.org/rfc/rfc5869.txt
/// </summary>
public class HkdfTests
{
    // ── RFC 5869 Appendix A.1 — Test Case 1 (Basic test case with SHA-256) ──
    // IKM  = 0x0b repeated 22 times
    // salt = 0x000102030405060708090a0b0c (13 octets)
    // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
    // L    = 42
    private static readonly byte[] Tc1Ikm = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    private static readonly byte[] Tc1Salt = Convert.FromHexString("000102030405060708090a0b0c");
    private static readonly byte[] Tc1Info = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9");

    // RFC 5869 Appendix A.1: PRK (32 octets)
    private static readonly byte[] Tc1Prk = Convert.FromHexString(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

    // RFC 5869 Appendix A.1: OKM (42 octets)
    private static readonly byte[] Tc1Okm = Convert.FromHexString(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    [Fact]
    public void Extract_Rfc5869TestCase1_MatchesExpectedPrk()
    {
        // RFC 5869 Appendix A.1: PRK = HMAC-SHA256(salt, IKM).
        var prk = Hkdf.Extract(HashAlgorithmName.SHA256, Tc1Ikm, Tc1Salt);

        prk.Should().Equal(Tc1Prk);
    }

    [Fact]
    public void Expand_Rfc5869TestCase1_MatchesExpectedOkm()
    {
        // RFC 5869 Appendix A.1: OKM = HKDF-Expand(PRK, info, L=42).
        var okm = Hkdf.Expand(HashAlgorithmName.SHA256, Tc1Prk, outputLength: 42, Tc1Info);

        okm.Should().Equal(Tc1Okm);
    }

    [Fact]
    public void DeriveKey_Rfc5869TestCase1_MatchesExpectedOkm()
    {
        // RFC 5869 Appendix A.1, end-to-end: OKM = Expand(Extract(salt, IKM), info, L=42).
        var okm = Hkdf.DeriveKey(HashAlgorithmName.SHA256, Tc1Ikm, outputLength: 42, Tc1Salt, Tc1Info);

        okm.Should().Equal(Tc1Okm);
    }

    // ── RFC 5869 Appendix A.3 — Test Case 3 (SHA-256, zero-length salt/info) ──
    // IKM  = 0x0b repeated 22 times
    // salt = (0 octets)
    // info = (0 octets)
    // L    = 42

    [Fact]
    public void Extract_Rfc5869TestCase3_ZeroLengthSalt_MatchesExpectedPrk()
    {
        // RFC 5869 Appendix A.3: PRK (32 octets). Per §2.2, absent salt is equivalent
        // to a string of HashLen zero bytes.
        var expectedPrk = Convert.FromHexString(
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");

        var prk = Hkdf.Extract(HashAlgorithmName.SHA256, Tc1Ikm, ReadOnlySpan<byte>.Empty);

        prk.Should().Equal(expectedPrk);
    }

    [Fact]
    public void DeriveKey_Rfc5869TestCase3_ZeroLengthSaltAndInfo_MatchesExpectedOkm()
    {
        // RFC 5869 Appendix A.3: OKM (42 octets) for zero-length salt and info.
        var expectedOkm = Convert.FromHexString(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

        var okm = Hkdf.DeriveKey(
            HashAlgorithmName.SHA256,
            Tc1Ikm,
            outputLength: 42,
            salt: ReadOnlySpan<byte>.Empty,
            info: ReadOnlySpan<byte>.Empty);

        okm.Should().Equal(expectedOkm);
    }

    // ── Input validation contract (FR-4 / Hkdf XML-doc exceptions) ──

    [Fact]
    public void Extract_UnsupportedHashAlgorithm_ThrowsArgumentException()
    {
        var act = () => Hkdf.Extract(HashAlgorithmName.MD5, Tc1Ikm, Tc1Salt);

        act.Should().Throw<ArgumentException>().WithParameterName("hashAlgorithm");
    }

    [Fact]
    public void Expand_UnsupportedHashAlgorithm_ThrowsArgumentException()
    {
        var act = () => Hkdf.Expand(HashAlgorithmName.MD5, Tc1Prk, outputLength: 42, Tc1Info);

        act.Should().Throw<ArgumentException>().WithParameterName("hashAlgorithm");
    }

    [Fact]
    public void DeriveKey_UnsupportedHashAlgorithm_ThrowsArgumentException()
    {
        var act = () => Hkdf.DeriveKey(HashAlgorithmName.MD5, Tc1Ikm, outputLength: 42, Tc1Salt, Tc1Info);

        act.Should().Throw<ArgumentException>().WithParameterName("hashAlgorithm");
    }

    [Fact]
    public void DeriveKey_ZeroOutputLength_ThrowsArgumentException()
    {
        var act = () => Hkdf.DeriveKey(HashAlgorithmName.SHA256, Tc1Ikm, outputLength: 0, Tc1Salt, Tc1Info);

        act.Should().Throw<ArgumentException>().WithParameterName("outputLength");
    }

    [Fact]
    public void DeriveKey_OutputLengthExceeds255TimesHashLen_ThrowsArgumentException()
    {
        // RFC 5869 §2.3: L <= 255 * HashLen; for SHA-256 the maximum is 255 * 32 = 8160 bytes.
        var act = () => Hkdf.DeriveKey(
            HashAlgorithmName.SHA256, Tc1Ikm, outputLength: 255 * 32 + 1, Tc1Salt, Tc1Info);

        act.Should().Throw<ArgumentException>().WithParameterName("outputLength");
    }

    [Fact]
    public void Expand_ZeroOutputLength_ThrowsArgumentException()
    {
        var act = () => Hkdf.Expand(HashAlgorithmName.SHA256, Tc1Prk, outputLength: 0, Tc1Info);

        act.Should().Throw<ArgumentException>().WithParameterName("outputLength");
    }

    [Fact]
    public void Expand_OutputLengthExceeds255TimesHashLen_ThrowsArgumentException()
    {
        // RFC 5869 §2.3: L <= 255 * HashLen; for SHA-256 the maximum is 255 * 32 = 8160 bytes.
        var act = () => Hkdf.Expand(HashAlgorithmName.SHA256, Tc1Prk, outputLength: 255 * 32 + 1, Tc1Info);

        act.Should().Throw<ArgumentException>().WithParameterName("outputLength");
    }

    [Fact]
    public void Expand_MaximumOutputLength_Succeeds()
    {
        // Boundary: exactly 255 * HashLen (8160 bytes for SHA-256) is the RFC 5869 §2.3 maximum.
        var okm = Hkdf.Expand(HashAlgorithmName.SHA256, Tc1Prk, outputLength: 255 * 32, Tc1Info);

        okm.Should().HaveCount(255 * 32);
    }
}
