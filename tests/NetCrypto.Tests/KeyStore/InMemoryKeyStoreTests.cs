using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.KeyStore;

public class InMemoryKeyStoreTests
{
    private readonly InMemoryKeyStore _store;
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    public InMemoryKeyStoreTests()
    {
        _store = new InMemoryKeyStore(_keyGen, _crypto);
    }

    [Fact]
    public async Task GenerateAsync_CreatesKey_ReturnsInfo()
    {
        var info = await _store.GenerateAsync("my-key", KeyType.Ed25519);

        info.Alias.Should().Be("my-key");
        info.KeyType.Should().Be(KeyType.Ed25519);
        info.PublicKey.Should().HaveCount(32);
    }

    [Fact]
    public async Task GenerateAsync_DuplicateAlias_Throws()
    {
        await _store.GenerateAsync("my-key", KeyType.Ed25519);

        var act = () => _store.GenerateAsync("my-key", KeyType.Ed25519);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task GetInfoAsync_ExistingKey_ReturnsInfo()
    {
        await _store.GenerateAsync("my-key", KeyType.Ed25519);

        var info = await _store.GetInfoAsync("my-key");

        info.Should().NotBeNull();
        info!.Alias.Should().Be("my-key");
    }

    [Fact]
    public async Task GetInfoAsync_NonExistentKey_ReturnsNull()
    {
        var info = await _store.GetInfoAsync("nonexistent");

        info.Should().BeNull();
    }

    [Fact]
    public async Task ImportAsync_StoresKeyPair()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var info = await _store.ImportAsync("imported", keyPair);

        info.Alias.Should().Be("imported");
        info.PublicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public async Task ImportAsync_DuplicateAlias_Throws()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        await _store.ImportAsync("imported", keyPair);

        var act = () => _store.ImportAsync("imported", keyPair);
        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task SignAsync_ExistingKey_ProducesValidSignature()
    {
        await _store.GenerateAsync("sign-key", KeyType.Ed25519);
        var info = await _store.GetInfoAsync("sign-key");
        var data = "test data"u8.ToArray();

        var signature = await _store.SignAsync("sign-key", data);

        signature.Should().HaveCount(64);

        // Verify signature is valid
        var valid = _crypto.Verify(KeyType.Ed25519, info!.PublicKey, data, signature);
        valid.Should().BeTrue();
    }

    [Fact]
    public async Task SignAsync_NonExistentKey_Throws()
    {
        var act = () => _store.SignAsync("nonexistent", "data"u8.ToArray());
        await act.Should().ThrowAsync<KeyNotFoundException>();
    }

    [Fact]
    public async Task CreateSignerAsync_ReturnsFunctionalSigner()
    {
        await _store.GenerateAsync("signer-key", KeyType.Ed25519);

        var signer = await _store.CreateSignerAsync("signer-key");

        signer.KeyType.Should().Be(KeyType.Ed25519);
        signer.PublicKey.Length.Should().Be(32);

        var data = "signer test"u8.ToArray();
        var signature = await signer.SignAsync(data);
        signature.Should().HaveCount(64);
    }

    [Fact]
    public async Task CreateSignerAsync_NonExistentKey_Throws()
    {
        var act = () => _store.CreateSignerAsync("nonexistent");
        await act.Should().ThrowAsync<KeyNotFoundException>();
    }

    [Fact]
    public async Task ListAsync_ReturnsAllAliases()
    {
        await _store.GenerateAsync("key-1", KeyType.Ed25519);
        await _store.GenerateAsync("key-2", KeyType.P256);

        var aliases = await _store.ListAsync();

        aliases.Should().HaveCount(2);
        aliases.Should().Contain("key-1");
        aliases.Should().Contain("key-2");
    }

    [Fact]
    public async Task ListAsync_EmptyStore_ReturnsEmpty()
    {
        var aliases = await _store.ListAsync();
        aliases.Should().BeEmpty();
    }

    [Fact]
    public async Task DeleteAsync_ExistingKey_ReturnsTrue()
    {
        await _store.GenerateAsync("delete-me", KeyType.Ed25519);

        var deleted = await _store.DeleteAsync("delete-me");

        deleted.Should().BeTrue();
        var info = await _store.GetInfoAsync("delete-me");
        info.Should().BeNull();
    }

    [Fact]
    public async Task DeleteAsync_NonExistentKey_ReturnsFalse()
    {
        var deleted = await _store.DeleteAsync("nonexistent");
        deleted.Should().BeFalse();
    }

    [Fact]
    public async Task MultipleKeyTypes_CoexistCorrectly()
    {
        await _store.GenerateAsync("ed25519-key", KeyType.Ed25519);
        await _store.GenerateAsync("p256-key", KeyType.P256);
        await _store.GenerateAsync("secp256k1-key", KeyType.Secp256k1);

        var ed = await _store.GetInfoAsync("ed25519-key");
        var p256 = await _store.GetInfoAsync("p256-key");
        var secp = await _store.GetInfoAsync("secp256k1-key");

        ed!.KeyType.Should().Be(KeyType.Ed25519);
        p256!.KeyType.Should().Be(KeyType.P256);
        secp!.KeyType.Should().Be(KeyType.Secp256k1);
    }
}
