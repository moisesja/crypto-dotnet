using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Issue #26 rule 8 — BBS multi-message signing by reference. This is the same shape issue #21
/// fixed for recoverable ECDSA: the primitive takes a raw private scalar
/// (<see cref="IBbsCryptoProvider.Sign"/>), which excludes exactly the keys a custody store
/// exists to hold.
/// </summary>
public class BbsByReferenceTests
{
    private static readonly byte[][] Messages =
    [
        "given-name=Ada"u8.ToArray(),
        "family-name=Lovelace"u8.ToArray(),
        "birth-year=1815"u8.ToArray(),
    ];

    private static KeyBbsSignRequest Request(string alias, KeyInstanceId instanceId, byte[] header) =>
        new(alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256,
            Messages.Select(m => new ReadOnlyMemory<byte>(m)).ToList(), header);

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task StoreHeldBbsSignature_VerifiesUnderTheProviderOracle()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);
        var info = await store.GetInfoAsync(alias, instanceId);
        var header = "mandatory-disclosure-group"u8.ToArray();

        var signature = await store.SignBbsAsync(Request(alias, instanceId, header));

        signature.Should().HaveCount(80);
        CapableStoreTestSupport.BbsProvider
            .Verify(info!.PublicKey, signature, Messages, header)
            .Should().BeTrue();
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task TheHeaderIsBoundIntoTheSignature()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);
        var info = await store.GetInfoAsync(alias, instanceId);

        var signature = await store.SignBbsAsync(Request(alias, instanceId, "header-a"u8.ToArray()));

        CapableStoreTestSupport.BbsProvider
            .Verify(info!.PublicKey, signature, Messages, "header-b"u8.ToArray())
            .Should().BeFalse("the header is committed at sign time");
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task AnEmptyHeaderIsHonoured()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);
        var info = await store.GetInfoAsync(alias, instanceId);

        var signature = await store.SignBbsAsync(Request(alias, instanceId, []));

        CapableStoreTestSupport.BbsProvider.Verify(info!.PublicKey, signature, Messages).Should().BeTrue();
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task BbsIsAdvertisedWhenTheImplementationIsAvailable()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();

        var capabilities = await store.GetCapabilitiesAsync();

        capabilities.Find(KeyType.Bls12381G2, KeyStoreOperation.BbsSign, KeyStoreAlgorithms.BbsBls12381Sha256)
            .Should().NotBeNull()
            .And.Match<KeyStoreCapability>(c => c!.MaxInputBytes > 0);
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task OversizeBbsInput_FailsBeforeTheProviderIsTouched()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);
        var capability = (await store.GetCapabilitiesAsync())
            .Find(KeyType.Bls12381G2, KeyStoreOperation.BbsSign, KeyStoreAlgorithms.BbsBls12381Sha256)!;

        var request = new KeyBbsSignRequest(alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256,
            [new byte[capability.MaxInputBytes], new byte[1]], ReadOnlyMemory<byte>.Empty);

        var act = () => store.SignBbsAsync(request);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task TheHeaderCountsTowardsTheBound()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);
        var capability = (await store.GetCapabilitiesAsync())
            .Find(KeyType.Bls12381G2, KeyStoreOperation.BbsSign, KeyStoreAlgorithms.BbsBls12381Sha256)!;

        var request = new KeyBbsSignRequest(alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256,
            [new byte[capability.MaxInputBytes]], new byte[1]);

        var act = () => store.SignBbsAsync(request);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task PlainBlsSigning_IsNeverAcceptedAsBbs()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        var asBbs = () => store.SignBbsAsync(new KeyBbsSignRequest(
            alias, instanceId, KeyStoreAlgorithms.Bls12381G2Basic,
            [new ReadOnlyMemory<byte>("m"u8.ToArray())], ReadOnlyMemory<byte>.Empty));
        (await asBbs.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unsupported);

        var asPlain = () => store.SignAsync(new KeySignRequest(
            alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256, "m"u8.ToArray()));
        (await asPlain.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unsupported);
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task ANonBlsKey_IsRefusedForBbs()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.Ed25519);

        var act = () => store.SignBbsAsync(Request(alias, instanceId, []));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unsupported);
    }

    // --- BBS-absent supported mode: these must pass on the no-native CI leg too ---

    [Fact]
    public async Task WithoutABbsProvider_BbsIsNotAdvertised_AndIsRefused()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        (await store.GetCapabilitiesAsync())
            .Capabilities.Should().NotContain(c => c.Operation == KeyStoreOperation.BbsSign);

        var act = () => store.SignBbsAsync(Request(alias, instanceId, []));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unsupported);
    }

    [Fact]
    public async Task WithAnUnavailableBbsProvider_BbsIsNotAdvertised_AndIsRefusedWithoutCallingIt()
    {
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", bbs: new UnavailableBbsProvider());
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        (await store.GetCapabilitiesAsync())
            .Capabilities.Should().NotContain(c => c.Operation == KeyStoreOperation.BbsSign);

        var act = () => store.SignBbsAsync(Request(alias, instanceId, []));

        // Unsupported, not BbsUnavailableException: an unavailable implementation is simply not
        // advertised, so the request never reaches the provider.
        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unsupported);
    }

    [Fact]
    public async Task AnEmptyMessageSet_IsAParameterFault()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        var act = () => store.SignBbsAsync(new KeyBbsSignRequest(
            alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256, [], ReadOnlyMemory<byte>.Empty));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    [Fact]
    public async Task ANullMessageList_IsAParameterFault()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        var act = () => store.SignBbsAsync(new KeyBbsSignRequest(
            alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256, null!, ReadOnlyMemory<byte>.Empty));

        await act.Should().ThrowAsync<ArgumentNullException>();
    }
}
