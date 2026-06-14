using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// Acceptance tests for PRD FR-7 (signing and key-store abstractions), netcrypto-prd.md §FR-7:
/// (a) <see cref="KeyPairSigner.SignAsync"/> output verifies via <see cref="ICryptoProvider.Verify(KeyType, ReadOnlySpan{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
///     for Ed25519 and P-256;
/// (b) a hand-written test-double <see cref="IKeyStore"/> proves <see cref="KeyStoreSigner"/> never
///     reads private key material — signing is delegated by alias; only alias-level public key and
///     <see cref="KeyType"/> handed to it at construction are exposed.
/// </summary>
public class KeyStoreSignerAcceptanceTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    // FR-7 acceptance criterion (netcrypto-prd.md §FR-7): "KeyPairSigner.SignAsync output verifies
    // via ICryptoProvider.Verify for Ed25519 and P-256."
    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task SignAsync_KeyPairSigner_OutputVerifiesViaDefaultCryptoProvider(KeyType keyType)
    {
        var keyPair = _keyGen.Generate(keyType);
        var signer = new KeyPairSigner(keyPair, _crypto);
        var data = "FR-7 acceptance payload"u8.ToArray();

        var signature = await signer.SignAsync(data);

        _crypto.Verify(keyType, keyPair.PublicKey, data, signature).Should().BeTrue();
    }

    // FR-7 acceptance criterion (netcrypto-prd.md §FR-7): "A test-double IKeyStore proves
    // KeyStoreSigner never reads private key material (signature delegated; only alias +
    // public key held)."
    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task SignAsync_KeyStoreSigner_DelegatesByAliasWithoutReadingPrivateKeyMaterial(KeyType keyType)
    {
        var keyPair = _keyGen.Generate(keyType);
        var store = new RecordingKeyStore(keyPair, _crypto);
        var signer = new KeyStoreSigner(store, "vault-alias", keyType, keyPair.PublicKey);
        var data = "key store signer acceptance"u8.ToArray();

        // Alias-level KeyType / public key come from construction, not from the store:
        // reading every signer property touches no store member at all.
        signer.KeyType.Should().Be(keyType);
        signer.PublicKey.ToArray().Should().Equal(keyPair.PublicKey);
        signer.MultibasePublicKey.Should().Be(keyPair.MultibasePublicKey);
        store.Calls.Should().BeEmpty("reading signer metadata must not touch the key store");

        var signature = await signer.SignAsync(data);

        // The only store interaction is SignAsync(alias, data). No other key-material-bearing
        // member (GenerateAsync, ImportAsync, GetInfoAsync, CreateSignerAsync, ListAsync,
        // DeleteAsync) was invoked — the double records every call and would have logged
        // (and thrown for) any of them.
        store.Calls.Should().ContainSingle().Which.Should().Be(nameof(IKeyStore.SignAsync));
        store.SignRequests.Should().ContainSingle();
        store.SignRequests[0].Alias.Should().Be("vault-alias");
        store.SignRequests[0].Data.Should().Equal(data);

        // The delegated signature round-trips against the public key.
        _crypto.Verify(keyType, keyPair.PublicKey, data, signature).Should().BeTrue();
    }

    /// <summary>
    /// Hand-written <see cref="IKeyStore"/> test double (deliberately not NSubstitute).
    /// It records every call and holds a real <see cref="KeyPair"/> internally; the private
    /// key is used exclusively inside <see cref="SignAsync"/> — mirroring an HSM-backed store
    /// where key material never crosses the store boundary. Every other member records the
    /// call and throws, so any forbidden access by <see cref="KeyStoreSigner"/> surfaces both
    /// in the call log and as a test failure.
    /// </summary>
    private sealed class RecordingKeyStore : IKeyStore
    {
        private readonly KeyPair _keyPair;
        private readonly ICryptoProvider _crypto;

        public RecordingKeyStore(KeyPair keyPair, ICryptoProvider crypto)
        {
            _keyPair = keyPair;
            _crypto = crypto;
        }

        public List<string> Calls { get; } = [];

        public List<(string Alias, byte[] Data)> SignRequests { get; } = [];

        public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            Calls.Add(nameof(SignAsync));
            SignRequests.Add((alias, data.ToArray()));

            // The private key is read here and only here, inside the store boundary.
            return Task.FromResult(_crypto.Sign(_keyPair.KeyType, _keyPair.PrivateKey, data.Span));
        }

        public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default)
            => throw Forbidden(nameof(GenerateAsync));

        public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
            => throw Forbidden(nameof(ImportAsync));

        public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default)
            => throw Forbidden(nameof(GetInfoAsync));

        public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
            => throw Forbidden(nameof(CreateSignerAsync));

        public Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
            => throw Forbidden(nameof(DeriveSharedSecretAsync));

        public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
            => throw Forbidden(nameof(ListAsync));

        public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
            => throw Forbidden(nameof(DeleteAsync));

        private InvalidOperationException Forbidden(string member)
        {
            Calls.Add(member);
            return new InvalidOperationException($"KeyStoreSigner must not call IKeyStore.{member}.");
        }
    }
}
