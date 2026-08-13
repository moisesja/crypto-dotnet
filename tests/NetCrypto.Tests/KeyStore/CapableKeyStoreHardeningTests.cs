using System.Collections;
using System.Reflection;
using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Regression tests for the defects the issue #26 adversarial pass and NFR-3 sweep found. Each
/// one fails if its guard is reverted, so this file is the record of what was actually wrong
/// rather than a restatement of what the code does.
/// </summary>
public class CapableKeyStoreHardeningTests
{
    private static readonly byte[] Payload = "payload"u8.ToArray();

    // ---------------------------------------------------------- output really speaks for the key

    [Fact]
    public async Task ASignatureMadeUnderADifferentKey_IsRejected()
    {
        // Length is not identity. A provider is an arbitrary injected implementation, and a
        // length-only check accepts a perfectly well-formed signature made under another key.
        using var attacker = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.P256);
        var crypto = new HostileCryptoProvider
        {
            SignReturns = () => attacker.WithPrivateKey(privateKey =>
                CapableStoreTestSupport.CryptoProvider.Sign(
                    KeyType.P256, privateKey, Payload, EcdsaSignatureFormat.IeeeP1363)),
        };

        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var act = () => store.SignAsync(new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, Payload));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    public async Task AWellFormedButMeaninglessDerSignature_IsRejected()
    {
        // DER is variable-width, so a length check cannot catch anything here — only verifying
        // against the advertised key can.
        var crypto = new HostileCryptoProvider { SignReturns = () => [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01] };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var act = () => store.SignAsync(new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256Der, Payload));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    public async Task AProviderThatAlsoLiesInVerify_CannotBlessItsOwnForgery()
    {
        // The output check runs through a private DefaultCryptoProvider, not the injected one,
        // so a provider cannot both forge a signature and certify it.
        var crypto = new AlwaysAgreeableProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.Ed25519);

        var act = () => store.SignAsync(new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Ed25519, Payload));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task AWellFormedButMeaninglessBbsSignature_IsRejected()
    {
        using var backend = new InMemoryKeyStoreBackend();
        var bbs = new HostileBbsProvider { SignReturns = () => Enumerable.Repeat((byte)0xAB, 80).ToArray() };
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", bbs: bbs);
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        var act = () => store.SignBbsAsync(new KeyBbsSignRequest(
            alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256,
            [new ReadOnlyMemory<byte>("m"u8.ToArray())], ReadOnlyMemory<byte>.Empty));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task ABbsProviderThatLiesInBothSignAndVerify_CannotBlessItsOwnForgery()
    {
        // PR #27 review: the earlier regression's fake lied only in Sign and delegated Verify to
        // the real provider — which is exactly the check a fully hostile provider defeats. The
        // BBS output check must run through a verifier independent of the producing provider,
        // mirroring what the ECDSA path already does.
        var bbs = new HostileBbsProvider
        {
            SignReturns = () => Enumerable.Repeat((byte)0xAB, 80).ToArray(),
            VerifyReturns = () => true,
        };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", bbs: bbs);
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        var act = () => store.SignBbsAsync(new KeyBbsSignRequest(
            alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256,
            [new ReadOnlyMemory<byte>("m"u8.ToArray())], ReadOnlyMemory<byte>.Empty));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    public async Task AnImportWhoseGeneratorFailsWithABackendError_SurfacesAsUnavailable()
    {
        // PR #27 review: only ArgumentException from FromPrivateKey was mapped, so a generator
        // failing with a backend/platform type escaped raw — after the material was consumed —
        // contradicting "no backend exception type escapes a capable-store member".
        using var backend = new InMemoryKeyStoreBackend();
        using var store = new CapableInMemoryKeyStore(
            backend, new KeyStoreNamespaceId("ns"), new BackendFailingGenerator(),
            CapableStoreTestSupport.CryptoProvider);

        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);

        var act = () => store.ImportAsync(new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k", material));

        var thrown = (await act.Should().ThrowAsync<KeyStoreException>()).Which;
        thrown.Error.Should().Be(KeyStoreError.Unavailable);
        thrown.InnerException.Should().BeOfType<DllNotFoundException>();
        (await store.ListAsync()).Should().BeEmpty("a failed ingestion must not commit a key");
        material.IsConsumed.Should().BeTrue("the store saw the secret, so the transfer is spent");
    }

    [Fact]
    public void WithExpressions_CannotProduceAnInconsistentOperationAlgorithmPair()
    {
        // PR #27 review: per-field init validation misses the cross-field invariant — mutating
        // Operation alone kept an algorithm on a Generate capability. Every publicly
        // constructible state must satisfy "algorithm present iff the operation selects one".
        var signing = new KeyStoreCapability(KeyType.P256, KeyStoreOperation.Sign, KeyStoreAlgorithms.Es256P1363, 1024);
        var generate = new KeyStoreCapability(KeyType.P256, KeyStoreOperation.Generate, null, 512);

        FluentActions.Invoking(() => signing with { Operation = KeyStoreOperation.Generate })
            .Should().Throw<ArgumentException>("Generate selects no algorithm, and this one still carries es256-p1363");
        FluentActions.Invoking(() => signing with { Operation = KeyStoreOperation.Import })
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => generate with { Operation = KeyStoreOperation.Sign })
            .Should().Throw<ArgumentException>("Sign requires an algorithm, and this one has none");

        // Same-family transitions keep the invariant and must keep working.
        FluentActions.Invoking(() => signing with { Operation = KeyStoreOperation.KeyAgreement }).Should().NotThrow();
        FluentActions.Invoking(() => generate with { Operation = KeyStoreOperation.Import }).Should().NotThrow();
    }

    [Theory]
    [InlineData(int.MaxValue)]
    [InlineData(-5)]
    public async Task AMessageListReportingAnAbsurdCount_IsRejectedBeforeAnyAllocation(int reportedCount)
    {
        // PR #27 review: the snapshot allocated new byte[count][] straight from the untrusted
        // Count. int.MaxValue produced OutOfMemoryException before any bound was consulted —
        // MaxInputBytes cannot help, because a count of zero-byte messages stays "within" it.
        var bbs = new HostileBbsProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", bbs: bbs);
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        var act = () => store.SignBbsAsync(new KeyBbsSignRequest(
            alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256,
            new CountLyingMessages(reportedCount), ReadOnlyMemory<byte>.Empty));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
        bbs.SignCalls.Should().Be(0);
    }

    [Fact]
    public async Task TheMessageCountBound_IsInclusive()
    {
        using var store = CapableStoreTestSupport.NewBbsStore();
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        var oneOver = Enumerable.Repeat(new ReadOnlyMemory<byte>("m"u8.ToArray()),
            CapableInMemoryKeyStore.MaxBbsMessageCount + 1).ToList();

        var act = () => store.SignBbsAsync(new KeyBbsSignRequest(
            alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256, oneOver, ReadOnlyMemory<byte>.Empty));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    [Fact]
    public async Task AReentrantKeyGenerator_IsRefusedOnTheLegacyGeneratePathToo()
    {
        // PR #27 LGTM note 2: the legacy overload generated the key before entering the
        // operation scope, so a reentrant generator was caught on one path but not the other.
        using var backend = new InMemoryKeyStoreBackend();
        CapableInMemoryKeyStore store = null!;
        using var _ = store = new CapableInMemoryKeyStore(
            backend, new KeyStoreNamespaceId("ns"),
            new ReentrantKeyGenerator(() => store.ListAsync().GetAwaiter().GetResult()),
            CapableStoreTestSupport.CryptoProvider);

        var act = () => store.GenerateAsync("k", KeyType.Ed25519);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .Where(e => e.Message.Contains("re-entered"));
        (await store.ListAsync()).Should().BeEmpty();
    }

    private sealed class BackendFailingGenerator : IKeyGenerator
    {
        public KeyPair Generate(KeyType keyType) => throw new DllNotFoundException("the HSM driver is missing");

        public KeyPair FromPrivateKey(KeyType keyType, ReadOnlySpan<byte> privateKey)
            => throw new DllNotFoundException("the HSM driver is missing");

        public PublicKeyReference FromPublicKey(KeyType keyType, ReadOnlySpan<byte> publicKey)
            => throw new DllNotFoundException("the HSM driver is missing");

        public KeyPair DeriveX25519FromEd25519(KeyPair ed25519KeyPair)
            => throw new DllNotFoundException("the HSM driver is missing");

        public PublicKeyReference DeriveX25519PublicKeyFromEd25519(ReadOnlySpan<byte> ed25519PublicKey)
            => throw new DllNotFoundException("the HSM driver is missing");
    }

    private sealed class ReentrantKeyGenerator(Action reenter) : IKeyGenerator
    {
        public KeyPair Generate(KeyType keyType)
        {
            reenter();
            return CapableStoreTestSupport.KeyGenerator.Generate(keyType);
        }

        public KeyPair FromPrivateKey(KeyType keyType, ReadOnlySpan<byte> privateKey)
            => CapableStoreTestSupport.KeyGenerator.FromPrivateKey(keyType, privateKey);

        public PublicKeyReference FromPublicKey(KeyType keyType, ReadOnlySpan<byte> publicKey)
            => CapableStoreTestSupport.KeyGenerator.FromPublicKey(keyType, publicKey);

        public KeyPair DeriveX25519FromEd25519(KeyPair ed25519KeyPair)
            => CapableStoreTestSupport.KeyGenerator.DeriveX25519FromEd25519(ed25519KeyPair);

        public PublicKeyReference DeriveX25519PublicKeyFromEd25519(ReadOnlySpan<byte> ed25519PublicKey)
            => CapableStoreTestSupport.KeyGenerator.DeriveX25519PublicKeyFromEd25519(ed25519PublicKey);
    }

    /// <summary>A list that lies about its Count; touching any element would be the failure.</summary>
    private sealed class CountLyingMessages(int reportedCount) : IReadOnlyList<ReadOnlyMemory<byte>>
    {
        public int Count => reportedCount;

        public ReadOnlyMemory<byte> this[int index] => ReadOnlyMemory<byte>.Empty;

        public IEnumerator<ReadOnlyMemory<byte>> GetEnumerator()
        {
            yield break;
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    // ---------------------------------------------------------- the fingerprint must be lossless

    // Built in-body rather than passed through [InlineData]: xUnit's theory-data serialization
    // rewrites a lone surrogate into U+FFFD, which is exactly the collision under test.
    private static IEnumerable<string> IllFormedAliases() =>
    [
        "\ud800",       // lone high surrogate
        "\udc00",       // lone low surrogate
        "a\ud800b",     // embedded
        "\ud800\ud800", // high followed by high
    ];

    [Fact]
    public async Task AnIllFormedAlias_IsRejectedRatherThanEncodedToTheReplacementCharacter()
    {
        // Encoding.UTF8 uses replacement fallback, so every unpaired surrogate — and U+FFFD
        // itself — encodes to the same three bytes (verified: "\ud800" → EF BF BD). Left
        // unchecked, two different requests share one mutation fingerprint and the second
        // silently replays the first, handing back a success receipt naming an alias the caller
        // never asked for while nothing exists at the alias they did ask for.
        using var store = CapableStoreTestSupport.NewStore();

        foreach (var alias in IllFormedAliases())
        {
            var act = () => store.GenerateAsync(
                new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), alias, KeyType.Ed25519));

            await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
        }

        (await store.ListAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task AWellFormedSurrogatePairAlias_KeepsWorking()
    {
        // The guard must reject ill-formed UTF-16, not astral-plane text.
        using var store = CapableStoreTestSupport.NewStore();

        var created = await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "wallet-😀-café", KeyType.Ed25519));

        created.Info.Alias.Should().Be("wallet-😀-café");
    }

    [Fact]
    public async Task DistinctAliasesThatCollideUnderReplacementFallback_DoNotReplayEachOther()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var operationId = CapableStoreTestSupport.NewOperationId();

        await store.GenerateAsync(new KeyGenerateRequest(operationId, "�", KeyType.Ed25519));

        // U+FFFD is a legal alias and encodes to the same bytes a lone surrogate would.
        var act = () => store.GenerateAsync(new KeyGenerateRequest(operationId, "\ud800", KeyType.Ed25519));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
        (await store.ListAsync()).Should().ContainSingle().Which.Should().Be("�");
    }

    [Fact]
    public void AnIllFormedIdentifier_IsRejectedAtConstruction()
    {
        FluentActions.Invoking(() => new KeyOperationId("\ud800")).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyInstanceId("\udc00")).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreNamespaceId("ns\ud800")).Should().Throw<ArgumentException>();

        // A well-formed surrogate PAIR is ordinary text and must keep working.
        FluentActions.Invoking(() => new KeyOperationId("😀")).Should().NotThrow();
        FluentActions.Invoking(() => new KeyOperationId("café")).Should().NotThrow();
    }

    [Fact]
    public async Task AnIllFormedInstanceId_CannotReplayADeleteThatNamedADifferentKey()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, _) = await store.SeedAsync("k", KeyType.Ed25519);
        var operationId = CapableStoreTestSupport.NewOperationId();

        var act = () => store.DeleteAsync(new KeyDeleteRequest(operationId, alias, new KeyInstanceId("x") with { Value = "x" }));
        await act.Should().NotThrowAsync();

        FluentActions.Invoking(() => new KeyInstanceId("\ud800")).Should().Throw<ArgumentException>();
    }

    // ---------------------------------------------------------- the bound must cover what is signed

    [Fact]
    [Trait("Category", "NativeFFI")]
    public async Task AMessageListWhoseEnumeratorAndIndexerDisagree_CannotSignPastTheBound()
    {
        // Messages is a caller-supplied IReadOnlyList, so its two read paths need not agree.
        // Bounding one and signing the other lets a hostile list sign far past the advertised
        // maximum — and defeats the deliberate long-accumulator overflow guard the same way.
        var bbs = new HostileBbsProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", bbs: bbs);
        var (alias, instanceId) = await store.SeedAsync("issuer", KeyType.Bls12381G2);

        var capability = (await store.GetCapabilitiesAsync())
            .Find(KeyType.Bls12381G2, KeyStoreOperation.BbsSign, KeyStoreAlgorithms.BbsBls12381Sha256)!;
        var messages = new ShapeShiftingMessages(
            enumerated: new byte[1],
            indexed: new byte[capability.MaxInputBytes + 1]);

        var act = () => store.SignBbsAsync(new KeyBbsSignRequest(
            alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256, messages, ReadOnlyMemory<byte>.Empty));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
        bbs.SignCalls.Should().Be(0, "the bound must be measured on the bytes that would actually be signed");
    }

    // ---------------------------------------------------------- import must not publish a lie

    [Fact]
    public async Task ImportingAPublicKeyThatDoesNotBelongToThePrivateKey_IsRejected()
    {
        // StoredKeyInfo.PublicKey is the verification identity downstream DID/VC code publishes.
        // An unchecked import lets it be set to a key unrelated to the one that will sign.
        using var real = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        using var decoy = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);

        var forged = real.WithPrivateKey(privateKey =>
            TransferableKeyMaterial.FromRawKey(KeyType.Ed25519, decoy.PublicKey, privateKey));

        using var store = CapableStoreTestSupport.NewStore();
        var act = () => store.ImportAsync(new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "forged", forged));

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("request");
        (await store.ListAsync()).Should().BeEmpty("nothing may be committed under a mismatched identity");
        forged.IsConsumed.Should().BeTrue("the store saw the secret, so the transfer is spent either way");
    }

    [Fact]
    public async Task AnHonestImportStillRoundTrips()
    {
        // The mismatch guard must not break the ordinary path.
        using var source = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.P256);
        var publicKey = source.PublicKey;
        var material = TransferableKeyMaterial.FromKeyPair(source);

        using var store = CapableStoreTestSupport.NewStore();
        var imported = await store.ImportAsync(
            new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k", material));

        imported.Info.PublicKey.Should().Equal(publicKey);

        var signature = await store.SignAsync(
            new KeySignRequest("k", imported.InstanceId, KeyStoreAlgorithms.Es256P1363, Payload));
        CapableStoreTestSupport.CryptoProvider
            .Verify(KeyType.P256, publicKey, Payload, signature, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue();
    }

    [Theory]
    [InlineData(KeyType.Ed25519, 32, 31)]
    [InlineData(KeyType.Ed25519, 31, 32)]
    [InlineData(KeyType.P256, 33, 1)]
    [InlineData(KeyType.P256, 1, 32)]
    [InlineData(KeyType.P384, 49, 32)]
    [InlineData(KeyType.Bls12381G2, 96, 48)]
    public void WrongLengthKeyMaterial_IsRejectedAtTheEntryPoint(KeyType keyType, int publicLength, int privateLength)
    {
        // NFR-3: a wrong-length raw key must surface as a parameter-named ArgumentException at
        // the entry point. Deferring it to first use means the material has already crossed the
        // custody boundary and had its metadata published as a real key.
        var act = () => TransferableKeyMaterial.FromRawKey(
            keyType, new byte[publicLength], Enumerable.Repeat((byte)7, privateLength).ToArray());

        act.Should().Throw<ArgumentException>();
    }

    // ---------------------------------------------------------- reentrancy

    [Fact]
    public async Task AProviderThatCallsBackIntoTheStore_IsRefusedRatherThanLetThroughTheLock()
    {
        // Monitor is reentrant, so without a guard a provider callback walks straight through
        // the backend lock. A nested delete then zeroizes the pinned buffer that the in-flight
        // KeyPair.WithPrivateKey borrow is still reading from, and the store returns a signature
        // for a key it has just destroyed.
        var crypto = new ReentrantCryptoProvider();
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        crypto.OnSign = () => store.DeleteAsync(alias).GetAwaiter().GetResult();

        var act = () => store.SignAsync(new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, Payload));

        var thrown = (await act.Should().ThrowAsync<KeyStoreException>()).Which;
        thrown.Error.Should().Be(KeyStoreError.Unavailable);
        thrown.InnerException.Should().BeOfType<InvalidOperationException>();
        (await store.GetInfoAsync(alias, instanceId)).Should().NotBeNull("the nested delete must not have happened");
    }

    [Fact]
    public async Task SequentialOperationsAreUnaffectedByTheReentrancyGuard()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        for (var i = 0; i < 5; i++)
            (await store.SignAsync(new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, Payload)))
                .Should().HaveCount(64);

        var signer = await store.CreateSignerAsync(alias);
        (await signer.SignAsync(Payload)).Should().NotBeEmpty();
    }

    // ---------------------------------------------------------- one alias grammar per store

    [Theory]
    [InlineData("a\0b")]
    [InlineData("a\nb")]
    public async Task TheLegacyMembersRejectAliasesTheCapableMembersCouldNeverAddress(string alias)
    {
        using var store = CapableStoreTestSupport.NewStore();

        var act = () => store.GenerateAsync(alias, KeyType.Ed25519);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
    }

    [Fact]
    public async Task TheLegacyMembersRejectAnOverLongAlias()
    {
        using var store = CapableStoreTestSupport.NewStore();

        var act = () => store.GenerateAsync(new string('a', 100_000), KeyType.Ed25519);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
    }

    [Fact]
    public async Task TheLegacyGenerateNamesItsParameterForAnUndefinedKeyType()
    {
        using var store = CapableStoreTestSupport.NewStore();

        var act = () => store.GenerateAsync("k", (KeyType)999);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("keyType");
    }

    // ---------------------------------------------------------- honest parameter names

    [Fact]
    public async Task NullMembersOfARequest_AreBlamedOnTheRequestParameter()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.Bls12381G2);

        await FluentActions.Awaiting(() => store.ImportAsync(
                new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k2", null!)))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("request");

        await FluentActions.Awaiting(() => store.SignBbsAsync(new KeyBbsSignRequest(
                alias, instanceId, KeyStoreAlgorithms.BbsBls12381Sha256, null!, ReadOnlyMemory<byte>.Empty)))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("request");
    }

    [Fact]
    public async Task AProviderInternalArgumentFault_IsNotBlamedOnTheCaller()
    {
        // Re-blaming the caller for a provider-internal bug points the operator at the wrong
        // side of the boundary, and tells the caller not to retry or fail over.
        var crypto = new HostileCryptoProvider
        {
            AgreeThrows = () => new ArgumentException("internal provider bug", "someInternalParam"),
        };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.X25519);

        var act = () => store.DeriveSharedSecretAsync(
            new KeyAgreementRequest(alias, instanceId, KeyStoreAlgorithms.EcdhX25519, new byte[32]));

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    [Fact]
    public async Task AProviderInventingACancellation_DoesNotMakeTheStoreClaimOneHappened()
    {
        var crypto = new HostileCryptoProvider { SignThrows = () => new OperationCanceledException() };
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns", crypto);
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var act = () => store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, Payload), CancellationToken.None);

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unavailable);
    }

    // ---------------------------------------------------------- doubles

    /// <summary>A list whose enumerator and indexer deliberately disagree.</summary>
    private sealed class ShapeShiftingMessages(byte[] enumerated, byte[] indexed) : IReadOnlyList<ReadOnlyMemory<byte>>
    {
        public int Count => 1;

        public ReadOnlyMemory<byte> this[int index] => indexed;

        public IEnumerator<ReadOnlyMemory<byte>> GetEnumerator()
        {
            yield return enumerated;
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    /// <summary>A provider that returns noise and then certifies it.</summary>
    private sealed class AlwaysAgreeableProvider : ICryptoProvider
    {
        public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
            => Enumerable.Repeat((byte)0xCD, 64).ToArray();

        public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, EcdsaSignatureFormat format)
            => Enumerable.Repeat((byte)0xCD, 64).ToArray();

        public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
            => true;

        public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format)
            => true;

        public byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey) => new byte[32];

        public byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
            => new byte[32];
    }

    /// <summary>A provider that calls back into the store from inside the signing call.</summary>
    private sealed class ReentrantCryptoProvider : ICryptoProvider
    {
        private readonly ICryptoProvider _inner = CapableStoreTestSupport.CryptoProvider;

        internal Action? OnSign { get; set; }

        public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
            => Sign(keyType, privateKey, data, EcdsaSignatureFormat.Der);

        public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, EcdsaSignatureFormat format)
        {
            OnSign?.Invoke();
            return _inner.Sign(keyType, privateKey, data, format);
        }

        public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
            => _inner.Verify(keyType, publicKey, data, signature);

        public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format)
            => _inner.Verify(keyType, publicKey, data, signature, format);

        public byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
            => _inner.KeyAgreement(privateKey, publicKey);

        public byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
            => _inner.DeriveSharedSecret(keyType, privateKey, publicKey);
    }
}

/// <summary>A BBS provider that reports available, counts calls, and can return chosen bytes.</summary>
internal sealed class HostileBbsProvider : IBbsCryptoProvider
{
    private readonly IBbsCryptoProvider _inner = CapableStoreTestSupport.BbsProvider;

    internal Func<byte[]>? SignReturns { get; set; }

    /// <summary>Returned instead of a real verification result, when set — a provider lying in both halves.</summary>
    internal Func<bool>? VerifyReturns { get; set; }

    internal int SignCalls { get; private set; }

    public BbsCiphersuite Ciphersuite => _inner.Ciphersuite;

    public bool IsAvailable => true;

    public byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages, ReadOnlySpan<byte> header = default)
    {
        SignCalls++;
        return SignReturns is { } producer ? producer() : _inner.Sign(privateKey, messages, header);
    }

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages, ReadOnlySpan<byte> header = default)
        => VerifyReturns is { } fabricated ? fabricated() : _inner.Verify(publicKey, signature, messages, header);

    public byte[] DeriveProof(ReadOnlySpan<byte> publicKey, byte[] signature, IReadOnlyList<byte[]> messages,
        IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> presentationHeader, ReadOnlySpan<byte> header = default)
        => _inner.DeriveProof(publicKey, signature, messages, revealedIndices, presentationHeader, header);

    public bool VerifyProof(ReadOnlySpan<byte> publicKey, byte[] proof, IReadOnlyList<byte[]> revealedMessages,
        IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> presentationHeader, ReadOnlySpan<byte> header = default)
        => _inner.VerifyProof(publicKey, proof, revealedMessages, revealedIndices, presentationHeader, header);
}
