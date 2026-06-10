using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

public class KeyPairSignerTests
{
    [Fact]
    public async Task SignAsync_DelegatesToCryptoProvider()
    {
        var keyGen = new DefaultKeyGenerator();
        var crypto = new DefaultCryptoProvider();
        var keyPair = keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, crypto);

        var data = "test data"u8.ToArray();
        var signature = await signer.SignAsync(data);

        signature.Should().HaveCount(64);

        // Verify the signature is valid
        var valid = crypto.Verify(KeyType.Ed25519, keyPair.PublicKey, data, signature);
        valid.Should().BeTrue();
    }

    [Fact]
    public void Properties_MatchKeyPair()
    {
        var keyGen = new DefaultKeyGenerator();
        var crypto = new DefaultCryptoProvider();
        var keyPair = keyGen.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, crypto);

        signer.KeyType.Should().Be(KeyType.Ed25519);
        signer.PublicKey.ToArray().Should().Equal(keyPair.PublicKey);
        signer.MultibasePublicKey.Should().Be(keyPair.MultibasePublicKey);
    }
}
