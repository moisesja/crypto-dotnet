using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Issue #26 rule 1 — discovery honesty is bidirectional. Every advertised tuple genuinely
/// works, and every unadvertised one is refused <em>before</em> any state change, never
/// silently downgraded.
/// </summary>
/// <remarks>
/// The expected algorithm table below is written out by hand on purpose. Deriving it from the
/// library's own table would make this test assert only that the code agrees with itself; the
/// point is to pin the identifiers, their key types, and their observable output sizes as a
/// specification.
/// </remarks>
public class CapabilityHonestyTests
{
    public static TheoryData<string, KeyType, int?> SignAlgorithms() => new()
    {
        // id, key type, exact signature length (null = DER, variable width)
        { "ed25519", KeyType.Ed25519, 64 },
        { "es256-der", KeyType.P256, null },
        { "es256-p1363", KeyType.P256, 64 },
        { "es384-der", KeyType.P384, null },
        { "es384-p1363", KeyType.P384, 96 },
        { "es512-der", KeyType.P521, null },
        { "es512-p1363", KeyType.P521, 132 },
        { "es256k", KeyType.Secp256k1, 64 },
        { "bls12381g1-basic", KeyType.Bls12381G1, 96 },
        { "bls12381g2-basic", KeyType.Bls12381G2, 48 },
    };

    public static TheoryData<string, KeyType, int> AgreementAlgorithms() => new()
    {
        { "ecdh-x25519", KeyType.X25519, 32 },
        { "ecdh-p256", KeyType.P256, 32 },
        { "ecdh-p384", KeyType.P384, 48 },
        { "ecdh-p521", KeyType.P521, 66 },
    };

    [Theory]
    [MemberData(nameof(SignAlgorithms))]
    public async Task EveryAdvertisedSignTuple_RoundTripsAgainstTheProviderOracle(
        string algorithmId, KeyType keyType, int? expectedLength)
    {
        using var store = CapableStoreTestSupport.NewStore();
        var algorithm = new KeyStoreAlgorithmId(algorithmId);

        var capabilities = await store.GetCapabilitiesAsync();
        capabilities.Find(keyType, KeyStoreOperation.Sign, algorithm)
            .Should().NotBeNull("the store must advertise every tuple this suite pins");

        var (alias, instanceId) = await store.SeedAsync($"k-{algorithmId}", keyType);
        var data = "the quick brown fox"u8.ToArray();

        var signature = await store.SignAsync(new KeySignRequest(alias, instanceId, algorithm, data));

        if (expectedLength is { } length)
            signature.Should().HaveCount(length);

        var info = await store.GetInfoAsync(alias, instanceId);
        var format = algorithmId.EndsWith("-der", StringComparison.Ordinal)
            ? EcdsaSignatureFormat.Der
            : EcdsaSignatureFormat.IeeeP1363;

        CapableStoreTestSupport.CryptoProvider
            .Verify(keyType, info!.PublicKey, data, signature, format)
            .Should().BeTrue("an advertised capability must genuinely work");
    }

    [Theory]
    [MemberData(nameof(AgreementAlgorithms))]
    public async Task EveryAdvertisedAgreementTuple_ProducesTheSameZAsTheExtractableEquivalent(
        string algorithmId, KeyType keyType, int expectedLength)
    {
        using var store = CapableStoreTestSupport.NewStore();
        var algorithm = new KeyStoreAlgorithmId(algorithmId);

        var (alias, instanceId) = await store.SeedAsync($"k-{algorithmId}", keyType);
        var storedInfo = await store.GetInfoAsync(alias, instanceId);

        using var peer = CapableStoreTestSupport.KeyGenerator.Generate(keyType);

        var fromStore = await store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, algorithm, peer.PublicKey));

        // ECDH is symmetric, so the peer computing Z from its own private key against the
        // store's public key is an oracle that never needs the store's private scalar.
        var fromPeer = peer.WithPrivateKey(privateKey =>
            CapableStoreTestSupport.CryptoProvider.DeriveSharedSecret(keyType, privateKey, storedInfo!.PublicKey));

        fromStore.Should().HaveCount(expectedLength);
        fromStore.Should().Equal(fromPeer);
    }

    public static TheoryData<KeyType, string> UnadvertisedSignTuples() => new()
    {
        { KeyType.X25519, "es256-p1363" },      // agreement-only key asked to sign
        { KeyType.Ed25519, "es256-der" },       // right operation, wrong curve for the id
        { KeyType.P256, "es384-p1363" },        // adjacent curve — the classic silent downgrade
        { KeyType.Secp256k1, "es256k-der" },    // an encoding variant that does not exist
        { KeyType.P256, "ES256-P1363" },        // identifiers are case-sensitive
        { KeyType.P256, "ecdh-p256" },          // an id from a different operation
        { KeyType.Bls12381G2, "bbs-bls12381-sha256" }, // BBS id on the plain signing path
        { KeyType.P256, "rs256" },              // a plausible JOSE name this store does not do
    };

    [Theory]
    [MemberData(nameof(UnadvertisedSignTuples))]
    public async Task UnadvertisedSignTuple_ThrowsUnsupported_AndChangesNothing(KeyType keyType, string algorithmId)
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", keyType);
        var before = await store.ListAsync();

        var act = () => store.SignAsync(
            new KeySignRequest(alias, instanceId, new KeyStoreAlgorithmId(algorithmId), new byte[] { 1, 2, 3 }));

        (await act.Should().ThrowAsync<KeyStoreException>())
            .Which.Error.Should().Be(KeyStoreError.Unsupported);

        (await store.ListAsync()).Should().Equal(before, "a refused operation must not change store contents");
        (await store.GetInfoAsync(alias, instanceId)).Should().NotBeNull();
    }

    [Fact]
    public async Task UnadvertisedGenerateKeyType_ThrowsUnsupported_BeforeCreatingAnything()
    {
        using var store = CapableStoreTestSupport.NewStore();

        // A key type outside the enum is by definition unadvertised.
        var act = () => store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", (KeyType)999));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
        (await store.ListAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task Discovery_IsSideEffectFree_AndStableAcrossCalls()
    {
        using var store = CapableStoreTestSupport.NewStore();

        var first = await store.GetCapabilitiesAsync();
        await store.SeedAsync("k", KeyType.Ed25519);
        var second = await store.GetCapabilitiesAsync();

        second.Revision.Should().Be(first.Revision, "the revision is stable for the instance lifetime");
        second.Should().Be(first);
        second.Capabilities.Should().Equal(first.Capabilities);
    }

    [Fact]
    public async Task CapabilitySet_IsNeverEmpty_AndEveryBoundIsPositiveAndFinite()
    {
        using var store = CapableStoreTestSupport.NewStore();

        var capabilities = await store.GetCapabilitiesAsync();

        capabilities.Capabilities.Should().NotBeEmpty();
        capabilities.Capabilities.Should().OnlyContain(c => c.MaxInputBytes > 0);
        capabilities.Revision.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task CapabilitySet_IsDeeplyImmutable()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var capabilities = await store.GetCapabilitiesAsync();

        var asList = capabilities.Capabilities as IList<KeyStoreCapability>;
        asList.Should().NotBeNull();
        asList!.Invoking(l => l.Add(new KeyStoreCapability(KeyType.Ed25519, KeyStoreOperation.Sign, new KeyStoreAlgorithmId("x"), 1)))
            .Should().Throw<NotSupportedException>("a discovery snapshot a caller can extend is not a snapshot");
    }

    [Fact]
    public void CapabilitySet_CopiesItsInput_SoALaterMutationCannotRewriteHistory()
    {
        var source = new List<KeyStoreCapability>
        {
            new(KeyType.Ed25519, KeyStoreOperation.Sign, new KeyStoreAlgorithmId("ed25519"), 1024),
        };

        var set = new KeyStoreCapabilitySet("rev-1", source);
        source.Add(new KeyStoreCapability(KeyType.P256, KeyStoreOperation.Generate, null, 32));

        set.Capabilities.Should().HaveCount(1);
    }

    [Fact]
    public async Task GenerateAndImport_AreAdvertisedForEveryKeyTypeWithoutAnAlgorithm()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var capabilities = await store.GetCapabilitiesAsync();

        foreach (var keyType in Enum.GetValues<KeyType>())
        {
            capabilities.Find(keyType, KeyStoreOperation.Generate).Should().NotBeNull();
            capabilities.Find(keyType, KeyStoreOperation.Import).Should().NotBeNull();
        }

        capabilities.Capabilities
            .Where(c => c.Operation is KeyStoreOperation.Generate or KeyStoreOperation.Import)
            .Should().OnlyContain(c => c.Algorithm == null);

        capabilities.Capabilities
            .Where(c => c.Operation is KeyStoreOperation.Sign or KeyStoreOperation.KeyAgreement or KeyStoreOperation.BbsSign)
            .Should().OnlyContain(c => c.Algorithm != null);
    }
}
