using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Issue #26 rule 2 — the algorithm identifier binds the <em>observable encoding</em>. This is
/// the gap that made format selection unreachable for a stored key: <c>EcdsaSignatureFormat</c>
/// existed, but only on the private-key path.
/// </summary>
public class AlgorithmEncodingTests
{
    [Fact]
    public async Task P1363Id_ProducesP1363Bytes_ThatDerVerificationRejects()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);
        var info = await store.GetInfoAsync(alias, instanceId);
        var data = "payload"u8.ToArray();

        var signature = await store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, data));

        signature.Should().HaveCount(64, "P1363 is fixed-width R‖S at the curve's field size");
        CapableStoreTestSupport.CryptoProvider
            .Verify(KeyType.P256, info!.PublicKey, data, signature, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue();
        CapableStoreTestSupport.CryptoProvider
            .Verify(KeyType.P256, info.PublicKey, data, signature, EcdsaSignatureFormat.Der)
            .Should().BeFalse("the encodings are not interchangeable — that is the point of separate ids");
    }

    [Fact]
    public async Task DerId_ProducesDerBytes_ThatP1363VerificationRejects()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);
        var info = await store.GetInfoAsync(alias, instanceId);
        var data = "payload"u8.ToArray();

        var signature = await store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256Der, data));

        signature[0].Should().Be(0x30, "a DER signature is an ASN.1 SEQUENCE");
        CapableStoreTestSupport.CryptoProvider
            .Verify(KeyType.P256, info!.PublicKey, data, signature, EcdsaSignatureFormat.Der)
            .Should().BeTrue();
        CapableStoreTestSupport.CryptoProvider
            .Verify(KeyType.P256, info.PublicKey, data, signature, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeFalse();
    }

    [Theory]
    [InlineData(KeyType.P256, 64)]
    [InlineData(KeyType.P384, 96)]
    [InlineData(KeyType.P521, 132)]
    public async Task P1363Widths_MatchTheCurveFieldSize(KeyType keyType, int expectedLength)
    {
        using var store = CapableStoreTestSupport.NewStore();
        var algorithm = keyType switch
        {
            KeyType.P256 => KeyStoreAlgorithms.Es256P1363,
            KeyType.P384 => KeyStoreAlgorithms.Es384P1363,
            _ => KeyStoreAlgorithms.Es512P1363,
        };

        var (alias, instanceId) = await store.SeedAsync("k", keyType);

        var signature = await store.SignAsync(new KeySignRequest(alias, instanceId, algorithm, "x"u8.ToArray()));

        signature.Should().HaveCount(expectedLength);
    }

    [Fact]
    public async Task Secp256k1_IsAlwaysFixedWidthCompact()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.Secp256k1);
        var data = "payload"u8.ToArray();
        var info = await store.GetInfoAsync(alias, instanceId);

        var signature = await store.SignAsync(new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256K, data));

        signature.Should().HaveCount(64);
        signature[0].Should().NotBe(0x30, "secp256k1 has no DER form here, so it cannot be an ASN.1 SEQUENCE");
        CapableStoreTestSupport.CryptoProvider
            .Verify(KeyType.Secp256k1, info!.PublicKey, data, signature)
            .Should().BeTrue();
    }

    [Fact]
    public async Task AlgorithmForADifferentCurve_FailsBeforeAnyBackendWork()
    {
        var crypto = new HostileCryptoProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P384);

        var act = () => store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, "x"u8.ToArray()));

        (await act.Should().ThrowAsync<KeyStoreException>())
            .Which.Error.Should().Be(KeyStoreError.Unsupported);
        crypto.SignCalls.Should().Be(0, "an algorithm/key mismatch must be caught before the provider is touched");
    }

    [Fact]
    public async Task AgreementAlgorithmForADifferentCurve_FailsBeforeAnyBackendWork()
    {
        var crypto = new HostileCryptoProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var act = () => store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, KeyStoreAlgorithms.EcdhP384, new byte[49]));

        (await act.Should().ThrowAsync<KeyStoreException>())
            .Which.Error.Should().Be(KeyStoreError.Unsupported);
        crypto.AgreeCalls.Should().Be(0);
    }

    [Fact]
    public async Task LegacySignAsync_KeepsTheDerDefault_Unchanged()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);
        var data = "payload"u8.ToArray();

        var legacy = await store.SignAsync(alias, data);
        var explicitDer = await store.SignAsync(new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256Der, data));

        legacy[0].Should().Be(0x30);
        explicitDer[0].Should().Be(0x30);
    }
}
