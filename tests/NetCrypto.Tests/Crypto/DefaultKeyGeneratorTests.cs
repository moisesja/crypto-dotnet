using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

public class DefaultKeyGeneratorTests
{
    private readonly DefaultKeyGenerator _generator = new();

    [Fact]
    public void Generate_Ed25519_ProducesValidKeyPair()
    {
        var keyPair = _generator.Generate(KeyType.Ed25519);

        keyPair.KeyType.Should().Be(KeyType.Ed25519);
        keyPair.PublicKey.Should().HaveCount(32);
        keyPair.PrivateKey.Should().NotBeEmpty();
    }

    [Fact]
    public void Generate_X25519_ProducesValidKeyPair()
    {
        var keyPair = _generator.Generate(KeyType.X25519);

        keyPair.KeyType.Should().Be(KeyType.X25519);
        keyPair.PublicKey.Should().HaveCount(32);
        keyPair.PrivateKey.Should().HaveCount(32);
    }

    [Fact]
    public void Generate_P256_ProducesValidKeyPair()
    {
        var keyPair = _generator.Generate(KeyType.P256);

        keyPair.KeyType.Should().Be(KeyType.P256);
        keyPair.PublicKey.Should().HaveCount(33); // compressed SEC1 point
        keyPair.PublicKey[0].Should().BeOneOf(0x02, 0x03);
        keyPair.PrivateKey.Should().HaveCount(32);
    }

    [Fact]
    public void Generate_P384_ProducesValidKeyPair()
    {
        var keyPair = _generator.Generate(KeyType.P384);

        keyPair.KeyType.Should().Be(KeyType.P384);
        keyPair.PublicKey.Should().HaveCount(49); // compressed SEC1 point
        keyPair.PublicKey[0].Should().BeOneOf(0x02, 0x03);
        keyPair.PrivateKey.Should().HaveCount(48);
    }

    [Fact]
    public void Generate_Secp256k1_ProducesValidKeyPair()
    {
        var keyPair = _generator.Generate(KeyType.Secp256k1);

        keyPair.KeyType.Should().Be(KeyType.Secp256k1);
        keyPair.PublicKey.Should().HaveCount(33); // compressed SEC1 point
        keyPair.PublicKey[0].Should().BeOneOf(0x02, 0x03);
        keyPair.PrivateKey.Should().HaveCount(32);
    }

    [Fact]
    public void FromPrivateKey_Ed25519_RestoresPublicKey()
    {
        var original = _generator.Generate(KeyType.Ed25519);
        var restored = _generator.FromPrivateKey(KeyType.Ed25519, original.PrivateKey);

        restored.PublicKey.Should().Equal(original.PublicKey);
    }

    [Fact]
    public void FromPrivateKey_Secp256k1_RestoresPublicKey()
    {
        var original = _generator.Generate(KeyType.Secp256k1);
        var restored = _generator.FromPrivateKey(KeyType.Secp256k1, original.PrivateKey);

        restored.PublicKey.Should().Equal(original.PublicKey);
    }

    [Fact]
    public void FromPublicKey_WrapsCorrectly()
    {
        var keyPair = _generator.Generate(KeyType.Ed25519);
        var pubRef = _generator.FromPublicKey(KeyType.Ed25519, keyPair.PublicKey);

        pubRef.KeyType.Should().Be(KeyType.Ed25519);
        pubRef.PublicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void DeriveX25519FromEd25519_ProducesValidX25519KeyPair()
    {
        var ed25519 = _generator.Generate(KeyType.Ed25519);
        var x25519 = _generator.DeriveX25519FromEd25519(ed25519);

        x25519.KeyType.Should().Be(KeyType.X25519);
        x25519.PublicKey.Should().HaveCount(32);
        x25519.PrivateKey.Should().HaveCount(32);
    }

    [Fact]
    public void DeriveX25519FromEd25519_DeterministicDerivation()
    {
        var ed25519 = _generator.Generate(KeyType.Ed25519);
        var x25519a = _generator.DeriveX25519FromEd25519(ed25519);
        var x25519b = _generator.DeriveX25519FromEd25519(ed25519);

        x25519a.PublicKey.Should().Equal(x25519b.PublicKey);
        x25519a.PrivateKey.Should().Equal(x25519b.PrivateKey);
    }

    [Fact]
    public void DeriveX25519FromEd25519_NonEd25519Key_ThrowsArgumentException()
    {
        var p256 = _generator.Generate(KeyType.P256);
        var act = () => _generator.DeriveX25519FromEd25519(p256);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void MultibasePublicKey_ProducesValidMultibaseString()
    {
        var keyPair = _generator.Generate(KeyType.Ed25519);
        keyPair.MultibasePublicKey.Should().StartWith("z"); // base58btc prefix
    }

    // --- BLS12-381 G1 ---

    [Fact]
    public void Generate_Bls12381G1_ProducesValidKeyPair()
    {
        var keyPair = _generator.Generate(KeyType.Bls12381G1);

        keyPair.KeyType.Should().Be(KeyType.Bls12381G1);
        keyPair.PublicKey.Should().HaveCount(48); // compressed G1 point
        keyPair.PrivateKey.Should().HaveCount(32);
    }

    [Fact]
    public void Generate_Bls12381G1_ProducesDifferentKeysEachTime()
    {
        var a = _generator.Generate(KeyType.Bls12381G1);
        var b = _generator.Generate(KeyType.Bls12381G1);

        a.PrivateKey.Should().NotEqual(b.PrivateKey);
        a.PublicKey.Should().NotEqual(b.PublicKey);
    }

    [Fact]
    public void FromPrivateKey_Bls12381G1_RestoresPublicKey()
    {
        var original = _generator.Generate(KeyType.Bls12381G1);
        var restored = _generator.FromPrivateKey(KeyType.Bls12381G1, original.PrivateKey);

        restored.PublicKey.Should().Equal(original.PublicKey);
        restored.PrivateKey.Should().Equal(original.PrivateKey);
    }

    // --- BLS12-381 G2 ---

    [Fact]
    public void Generate_Bls12381G2_ProducesValidKeyPair()
    {
        var keyPair = _generator.Generate(KeyType.Bls12381G2);

        keyPair.KeyType.Should().Be(KeyType.Bls12381G2);
        keyPair.PublicKey.Should().HaveCount(96); // compressed G2 point
        keyPair.PrivateKey.Should().HaveCount(32);
    }

    [Fact]
    public void Generate_Bls12381G2_ProducesDifferentKeysEachTime()
    {
        var a = _generator.Generate(KeyType.Bls12381G2);
        var b = _generator.Generate(KeyType.Bls12381G2);

        a.PrivateKey.Should().NotEqual(b.PrivateKey);
        a.PublicKey.Should().NotEqual(b.PublicKey);
    }

    [Fact]
    public void FromPrivateKey_Bls12381G2_RestoresPublicKey()
    {
        var original = _generator.Generate(KeyType.Bls12381G2);
        var restored = _generator.FromPrivateKey(KeyType.Bls12381G2, original.PrivateKey);

        restored.PublicKey.Should().Equal(original.PublicKey);
        restored.PrivateKey.Should().Equal(original.PrivateKey);
    }
}
