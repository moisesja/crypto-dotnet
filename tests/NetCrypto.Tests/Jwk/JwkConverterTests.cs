using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Jwk;

public class JwkConverterTests
{
    private readonly DefaultKeyGenerator _keyGen = new();

    [Fact]
    public void ToPublicJwk_Ed25519_ProducesCorrectFormat()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        jwk.Kty.Should().Be("OKP");
        jwk.Crv.Should().Be("Ed25519");
        jwk.X.Should().NotBeNullOrEmpty();
        jwk.D.Should().BeNull();
    }

    [Fact]
    public void ToPublicJwk_X25519_ProducesCorrectFormat()
    {
        var keyPair = _keyGen.Generate(KeyType.X25519);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        jwk.Kty.Should().Be("OKP");
        jwk.Crv.Should().Be("X25519");
        jwk.X.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ToPublicJwk_P256_ProducesCorrectFormat()
    {
        var keyPair = _keyGen.Generate(KeyType.P256);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        jwk.Kty.Should().Be("EC");
        jwk.Crv.Should().Be("P-256");
        jwk.X.Should().NotBeNullOrEmpty();
        jwk.Y.Should().NotBeNullOrEmpty();
        jwk.D.Should().BeNull();
    }

    [Fact]
    public void ToPublicJwk_P384_ProducesCorrectFormat()
    {
        var keyPair = _keyGen.Generate(KeyType.P384);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        jwk.Kty.Should().Be("EC");
        jwk.Crv.Should().Be("P-384");
        jwk.X.Should().NotBeNullOrEmpty();
        jwk.Y.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ToPublicJwk_P521_ProducesCorrectFormat()
    {
        var keyPair = _keyGen.Generate(KeyType.P521);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        jwk.Kty.Should().Be("EC");
        jwk.Crv.Should().Be("P-521"); // RFC 7518 §6.2.1.1 — exact case-sensitive name
        jwk.X.Should().NotBeNullOrEmpty();
        jwk.Y.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ToPublicJwk_Secp256k1_ProducesCorrectFormat()
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        jwk.Kty.Should().Be("EC");
        jwk.Crv.Should().Be("secp256k1");
        jwk.X.Should().NotBeNullOrEmpty();
        jwk.Y.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ToPrivateJwk_IncludesDParameter()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var jwk = JwkConverter.ToPrivateJwk(keyPair);

        jwk.Kty.Should().Be("OKP");
        jwk.D.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ExtractPublicKey_Ed25519_RoundTrips()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(jwk);

        keyType.Should().Be(KeyType.Ed25519);
        publicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void ExtractPublicKey_X25519_RoundTrips()
    {
        var keyPair = _keyGen.Generate(KeyType.X25519);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(jwk);

        keyType.Should().Be(KeyType.X25519);
        publicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void ExtractPublicKey_P256_RoundTrips()
    {
        var keyPair = _keyGen.Generate(KeyType.P256);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(jwk);

        keyType.Should().Be(KeyType.P256);
        publicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void ExtractPublicKey_P384_RoundTrips()
    {
        var keyPair = _keyGen.Generate(KeyType.P384);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(jwk);

        keyType.Should().Be(KeyType.P384);
        publicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void ExtractPublicKey_P521_RoundTrips()
    {
        var keyPair = _keyGen.Generate(KeyType.P521);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(jwk);

        keyType.Should().Be(KeyType.P521);
        publicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void ExtractPublicKey_Secp256k1_RoundTrips()
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var jwk = JwkConverter.ToPublicJwk(keyPair);

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(jwk);

        keyType.Should().Be(KeyType.Secp256k1);
        publicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void ExtractPublicKey_UnsupportedKty_Throws()
    {
        var jwk = new Microsoft.IdentityModel.Tokens.JsonWebKey { Kty = "RSA" };

        var act = () => JwkConverter.ExtractPublicKey(jwk);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ExtractPublicKey_UnsupportedOkpCrv_Throws()
    {
        var jwk = new Microsoft.IdentityModel.Tokens.JsonWebKey { Kty = "OKP", Crv = "Ed448" };

        var act = () => JwkConverter.ExtractPublicKey(jwk);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ExtractPublicKey_UnsupportedEcCrv_Throws()
    {
        // brainpoolP256r1 is a defined IANA EC curve but not supported by this library.
        var jwk = new Microsoft.IdentityModel.Tokens.JsonWebKey { Kty = "EC", Crv = "brainpoolP256r1" };

        var act = () => JwkConverter.ExtractPublicKey(jwk);
        act.Should().Throw<ArgumentException>();
    }
}
