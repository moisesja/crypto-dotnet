using System.Numerics;
using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using NetCid;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// Issue #63 — invalid-curve attack defense. NIST point validation MUST reject off-curve
/// public keys at the JWK import boundary, so consumers cannot inherit the vulnerability
/// by doing ExtractPublicKey → DeriveSharedSecret.
/// </summary>
public class EcPointValidatorTests
{
    private readonly DefaultKeyGenerator _keyGen = new();

    // -------- Direct validator API --------

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    public void EnsureOnCurve_GeneratedKey_DoesNotThrow(KeyType keyType)
    {
        var keyPair = _keyGen.Generate(keyType);

        // Decompress the freshly generated compressed point to get explicit (X, Y).
        var (x, y) = DecompressForValidation(keyType, keyPair.PublicKey);

        var act = () => EcPointValidator.EnsureOnCurve(keyType, x, y);
        act.Should().NotThrow();
    }

    [Theory]
    [InlineData(KeyType.P256, 32)]
    [InlineData(KeyType.P384, 48)]
    [InlineData(KeyType.P521, 66)]
    [InlineData(KeyType.Secp256k1, 32)]
    public void EnsureOnCurve_PointAtInfinity_Throws(KeyType keyType, int coordLen)
    {
        var zero = new byte[coordLen];

        var act = () => EcPointValidator.EnsureOnCurve(keyType, zero, zero);
        act.Should().Throw<CryptographicException>().WithMessage("*identity*");
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    public void EnsureOnCurve_OffCurvePoint_Throws(KeyType keyType)
    {
        // Take a real point and flip one bit in Y. The result still has valid coordinate
        // lengths but no longer satisfies y² ≡ x³ + a·x + b (mod p).
        var keyPair = _keyGen.Generate(keyType);
        var (x, y) = DecompressForValidation(keyType, keyPair.PublicKey);
        y[0] ^= 0x01;

        var act = () => EcPointValidator.EnsureOnCurve(keyType, x, y);
        act.Should().Throw<CryptographicException>().WithMessage("*not on the stated curve*");
    }

    [Fact]
    public void EnsureOnCurve_CoordinateOutOfRange_Throws()
    {
        // P-256 prime p; (p, 0) is out of range (x must be < p).
        var pHex = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        var xAtP = Convert.FromHexString(pHex);
        var yZero = new byte[32];

        var act = () => EcPointValidator.EnsureOnCurve(KeyType.P256, xAtP, yZero);
        act.Should().Throw<CryptographicException>().WithMessage("*out of range*");
    }

    [Fact]
    public void EnsureOnCurve_YCoordinateOutOfRange_Throws()
    {
        // The y >= p half of the range check (only x = p is covered above).
        var pHex = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        var xOne = new byte[32];
        xOne[^1] = 1;
        var yAtP = Convert.FromHexString(pHex);

        var act = () => EcPointValidator.EnsureOnCurve(KeyType.P256, xOne, yAtP);
        act.Should().Throw<CryptographicException>().WithMessage("*out of range*");
    }

    [Fact]
    public void EnsureOnCurve_ArbitraryOffCurvePoint_Throws()
    {
        // A small, deterministic (x, y) = (2, 3) that is not derived from any real point and does
        // not satisfy the P-256 curve equation — the genuine invalid-curve case, not a bit-flip.
        var x = new byte[32];
        x[^1] = 2;
        var y = new byte[32];
        y[^1] = 3;

        var act = () => EcPointValidator.EnsureOnCurve(KeyType.P256, x, y);
        act.Should().Throw<CryptographicException>().WithMessage("*not on the stated curve*");
    }

    [Fact]
    public void EnsureOnCurve_NonEcKeyType_IsNoop()
    {
        // Ed25519 / X25519 / BLS aren't NIST curves; the validator silently returns.
        var dummy = new byte[32];

        var act = () => EcPointValidator.EnsureOnCurve(KeyType.Ed25519, dummy, dummy);
        act.Should().NotThrow();
    }

    // -------- JWK boundary validation (the security-critical path) --------

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    public void ExtractPublicKey_OffCurveJwk_Throws(KeyType keyType)
    {
        // Build a JWK whose (x, y) coordinates do not lie on the stated curve.
        var keyPair = _keyGen.Generate(keyType);
        var jwk = JwkConverter.ToPublicJwk(keyType, keyPair.PublicKey);

        // Flip one bit in Y so the point is no longer on the curve.
        var yBytes = Multibase.Decode("u" + jwk.Y);
        yBytes[0] ^= 0x01;
        jwk.Y = Multibase.Encode(yBytes, MultibaseEncoding.Base64Url, includePrefix: false);

        var act = () => JwkConverter.ExtractPublicKey(jwk);
        act.Should().Throw<CryptographicException>().WithMessage("*not on the stated curve*");
    }

    [Theory]
    [InlineData("P-256", 32)]
    [InlineData("P-384", 48)]
    [InlineData("P-521", 66)]
    [InlineData("secp256k1", 32)]
    public void ExtractPublicKey_IdentityJwk_Throws(string crv, int coordLen)
    {
        var zero = new byte[coordLen];
        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Crv = crv,
            X = Multibase.Encode(zero, MultibaseEncoding.Base64Url, includePrefix: false),
            Y = Multibase.Encode(zero, MultibaseEncoding.Base64Url, includePrefix: false)
        };

        var act = () => JwkConverter.ExtractPublicKey(jwk);
        act.Should().Throw<CryptographicException>().WithMessage("*identity*");
    }

    [Fact]
    public void ExtractPublicKey_CoordinateAtPrime_Throws()
    {
        // P-256 prime exactly equals p; reject as out-of-range.
        var pHex = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        var jwk = new JsonWebKey
        {
            Kty = "EC",
            Crv = "P-256",
            X = Multibase.Encode(Convert.FromHexString(pHex), MultibaseEncoding.Base64Url, includePrefix: false),
            Y = Multibase.Encode(new byte[32], MultibaseEncoding.Base64Url, includePrefix: false)
        };

        var act = () => JwkConverter.ExtractPublicKey(jwk);
        act.Should().Throw<CryptographicException>().WithMessage("*out of range*");
    }

    [Fact]
    public void ExtractPublicKey_ValidJwk_StillRoundTrips()
    {
        var keyPair = _keyGen.Generate(KeyType.P256);
        var jwk = JwkConverter.ToPublicJwk(KeyType.P256, keyPair.PublicKey);

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(jwk);

        keyType.Should().Be(KeyType.P256);
        publicKey.Should().Equal(keyPair.PublicKey);
    }

    // -------- Decompression validation (defense in depth) --------

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    public void DecompressEcPoint_AcceptsRealKey(KeyType keyType)
    {
        // The freshly generated compressed key should round-trip cleanly through the
        // decompression + on-curve validation path.
        var keyPair = _keyGen.Generate(keyType);
        var curve = keyType switch
        {
            KeyType.P256 => ECCurve.NamedCurves.nistP256,
            KeyType.P384 => ECCurve.NamedCurves.nistP384,
            KeyType.P521 => ECCurve.NamedCurves.nistP521,
            _ => throw new InvalidOperationException()
        };

        var act = () => DefaultCryptoProvider.DecompressEcPoint(keyPair.PublicKey, curve);
        act.Should().NotThrow();
    }

    // -------- Helpers --------

    private static (byte[] X, byte[] Y) DecompressForValidation(KeyType keyType, byte[] compressed)
    {
        if (keyType == KeyType.Secp256k1)
            return DefaultCryptoProvider.DecompressSecp256k1Point(compressed);

        var curve = keyType switch
        {
            KeyType.P256 => ECCurve.NamedCurves.nistP256,
            KeyType.P384 => ECCurve.NamedCurves.nistP384,
            KeyType.P521 => ECCurve.NamedCurves.nistP521,
            _ => throw new InvalidOperationException()
        };
        var p = DefaultCryptoProvider.DecompressEcPoint(compressed, curve);
        return (p.Q.X!, p.Q.Y!);
    }
}
