using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// NFR-3 across the issue #26 surface, in all three input families: (a) absent, (b) wrong-shape,
/// and (c) structurally valid but semantically wrong — the family where the defects hide.
/// </summary>
/// <remarks>
/// A <c>readonly record struct</c> always has a <c>default</c> whose value is <c>null</c>, and a
/// <c>with</c> expression bypasses a constructor check. Neither hole is closable by the type
/// itself, so the store re-validates every identifier at every entry point and reports it
/// against its own parameter. Both holes are exercised below.
/// </remarks>
public class CapableKeyStoreInputValidationTests
{
    private static readonly byte[] Data = "x"u8.ToArray();

    // ---------------------------------------------------------- identifier value types

    [Theory]
    [InlineData("")]
    [InlineData("with\0null")]
    [InlineData("with\nnewline")]
    [InlineData("with\ttab")]
    public void IdentifierConstructors_RejectEmptyAndControlCharacters(string value)
    {
        FluentActions.Invoking(() => new KeyStoreNamespaceId(value)).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyInstanceId(value)).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyOperationId(value)).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreAlgorithmId(value)).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void IdentifierConstructors_RejectNull()
    {
        FluentActions.Invoking(() => new KeyInstanceId(null!)).Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void IdentifierConstructors_RejectOverLongValues()
    {
        var tooLong = new string('a', 513);

        FluentActions.Invoking(() => new KeyOperationId(tooLong)).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyOperationId(new string('a', 512))).Should().NotThrow();
    }

    [Fact]
    public void IdentifierToString_IsSafeOnADefaultInstance()
    {
        default(KeyInstanceId).ToString().Should().BeEmpty();
        default(KeyOperationId).ToString().Should().BeEmpty();
        default(KeyStoreNamespaceId).ToString().Should().BeEmpty();
        default(KeyStoreAlgorithmId).ToString().Should().BeEmpty();
    }

    // ---------------------------------------------------------- (a) absent

    [Fact]
    public async Task NullRequests_AreArgumentNullExceptions()
    {
        using var store = CapableStoreTestSupport.NewStore();

        await FluentActions.Awaiting(() => store.GenerateAsync((KeyGenerateRequest)null!))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("request");
        await FluentActions.Awaiting(() => store.ImportAsync((KeyImportRequest)null!))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("request");
        await FluentActions.Awaiting(() => store.DeleteAsync((KeyDeleteRequest)null!))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("request");
        await FluentActions.Awaiting(() => store.SignAsync((KeySignRequest)null!))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("request");
        await FluentActions.Awaiting(() => store.SignBbsAsync(null!))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("request");
        await FluentActions.Awaiting(() => store.DeriveSharedSecretAsync((KeyAgreementRequest)null!))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("request");
    }

    [Fact]
    public async Task NullAliases_AreParameterFaults()
    {
        using var store = CapableStoreTestSupport.NewStore();

        await FluentActions.Awaiting(() => store.GetInfoAsync(null!, new KeyInstanceId("i")))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
        await FluentActions.Awaiting(() => store.GetInfoAsync("", new KeyInstanceId("i")))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
    }

    // ---------------------------------------------------------- (c) the default(T) hole

    [Fact]
    public async Task DefaultIdentifiers_AreRejectedAgainstTheCallersParameter()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        await FluentActions.Awaiting(() => store.GenerateAsync(new KeyGenerateRequest(default, "k2", KeyType.P256)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");

        await FluentActions.Awaiting(() => store.SignAsync(new KeySignRequest(alias, default, KeyStoreAlgorithms.Es256P1363, Data)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");

        await FluentActions.Awaiting(() => store.SignAsync(new KeySignRequest(alias, instanceId, default, Data)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");

        await FluentActions.Awaiting(() => store.DeriveSharedSecretAsync(
                new KeyAgreementRequest(alias, instanceId, default, Data)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");

        await FluentActions.Awaiting(() => store.DeleteAsync(new KeyDeleteRequest(default, alias, instanceId)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");

        await FluentActions.Awaiting(() => store.DeleteAsync(new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), alias, default)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");

        await FluentActions.Awaiting(() => store.GetInfoAsync(alias, default(KeyInstanceId)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("instanceId");

        await FluentActions.Awaiting(() => store.GetMutationOutcomeAsync(KeyMutationKind.Generate, default))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("operationId");
    }

    [Fact]
    public async Task ABareDefaultLiteral_BindsToTheAliasOnlyQuery_NotToAnUncheckedInstanceLookup()
    {
        // Pinning test for a sharp edge in the overload pair, so it cannot change silently.
        // `GetInfoAsync(alias, default)` binds to the inherited IKeyStore overload — `default`
        // is target-typed and CancellationToken matches without needing an optional argument.
        // That is the right semantic (a bare `default` supplies no instance identity at all),
        // and it is NOT a downgrade of a supplied one: a variable of type KeyInstanceId binds
        // to the instance-bearing overload at compile time and is validated, as asserted above.
        using var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);

        var viaBareDefault = await store.GetInfoAsync(alias, default);

        viaBareDefault.Should().NotBeNull();
        viaBareDefault!.InstanceId.Should().Be(instanceId);
    }

    [Fact]
    public void WithExpressions_CannotInstallAValueTheConstructorWouldReject()
    {
        // A property *initializer* runs only in the primary constructor, so `with` skips it.
        // Every one of these validates on the `init` accessor instead, which `with` does call.
        var id = new KeyInstanceId("valid");
        FluentActions.Invoking(() => id with { Value = "" }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => id with { Value = null! }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => id with { Value = new string('a', 513) }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => id with { Value = "with\0null" }).Should().Throw<ArgumentException>();

        FluentActions.Invoking(() => new KeyStoreNamespaceId("ns") with { Value = "" }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyOperationId("op") with { Value = "" }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreAlgorithmId("alg") with { Value = "" }).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void WithExpressions_CannotPoisonACapabilityOrACapabilitySet()
    {
        var signing = new KeyStoreCapability(KeyType.Ed25519, KeyStoreOperation.Sign, KeyStoreAlgorithms.Ed25519, 1024);
        var generate = new KeyStoreCapability(KeyType.Ed25519, KeyStoreOperation.Generate, null, 512);

        FluentActions.Invoking(() => signing with { MaxInputBytes = 0 }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => signing with { MaxInputBytes = int.MinValue }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => signing with { KeyType = (KeyType)999 }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => signing with { Operation = (KeyStoreOperation)42 }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => signing with { Algorithm = null }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => generate with { Algorithm = KeyStoreAlgorithms.Ed25519 }).Should().Throw<ArgumentException>();

        var set = new KeyStoreCapabilitySet("rev-1", [signing]);
        FluentActions.Invoking(() => set with { Revision = "" }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => set with { Revision = null! }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => set with { Capabilities = null! }).Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => set with { Capabilities = [signing, null!] }).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => set with { Capabilities = [signing, signing] }).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AWithExpression_StillCopiesTheCapabilityList()
    {
        // The doc promises the caller's list cannot change what a store advertises. That has to
        // hold through `with` too, or a poisoned set keeps a live handle to the caller's list.
        var live = new List<KeyStoreCapability>
        {
            new(KeyType.Ed25519, KeyStoreOperation.Sign, KeyStoreAlgorithms.Ed25519, 1024),
        };
        var set = new KeyStoreCapabilitySet("rev-1", []) with { Capabilities = live };

        live.Clear();

        set.Capabilities.Should().HaveCount(1);
        set.Find(KeyType.Ed25519, KeyStoreOperation.Sign, KeyStoreAlgorithms.Ed25519).Should().NotBeNull();
    }

    [Fact]
    public void AMutationResult_CannotHaveItsInfoNulled()
    {
        var info = new StoredKeyInfo { Alias = "k", KeyType = KeyType.Ed25519, PublicKey = new byte[32] };
        var result = new KeyMutationResult(info, new KeyInstanceId("i"), Replayed: false);

        FluentActions.Invoking(() => new KeyMutationResult(null!, new KeyInstanceId("i"), false))
            .Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => result with { Info = null! }).Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AnUndefinedErrorClassificationIsRejected()
    {
        // Every caller switches on Error; an unrecognized value falls silently to the default arm.
        FluentActions.Invoking(() => new KeyStoreException((KeyStoreError)42, "m"))
            .Should().Throw<ArgumentException>().WithParameterName("error");
    }

    // ---------------------------------------------------------- (b)/(c) aliases

    [Theory]
    [InlineData("")]
    [InlineData("control\0char")]
    public async Task MalformedAliases_AreParameterFaults(string alias)
    {
        using var store = CapableStoreTestSupport.NewStore();

        await FluentActions.Awaiting(() => store.GenerateAsync(
                new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), alias, KeyType.Ed25519)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    [Fact]
    public async Task AnOverLongAlias_IsMeasuredInUtf8Bytes()
    {
        using var store = CapableStoreTestSupport.NewStore();

        // 200 characters, but 800 UTF-8 bytes — a character-count check would let this through.
        var alias = new string('中', 200);

        await FluentActions.Awaiting(() => store.GenerateAsync(
                new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), alias, KeyType.Ed25519)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");

        (await store.ListAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task AnUndefinedKeyType_IsAParameterFault()
    {
        using var store = CapableStoreTestSupport.NewStore();

        await FluentActions.Awaiting(() => store.GenerateAsync(
                new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", (KeyType)42)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("request");
    }

    [Fact]
    public async Task AnUndefinedMutationKind_IsAParameterFault()
    {
        using var store = CapableStoreTestSupport.NewStore();

        await FluentActions.Awaiting(() => store.GetMutationOutcomeAsync((KeyMutationKind)42, CapableStoreTestSupport.NewOperationId()))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("kind");
    }

    // ---------------------------------------------------------- capability value types

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void ACapabilityBoundMustBePositive(int maxInputBytes)
    {
        FluentActions.Invoking(() => new KeyStoreCapability(
                KeyType.Ed25519, KeyStoreOperation.Sign, KeyStoreAlgorithms.Ed25519, maxInputBytes))
            .Should().Throw<ArgumentException>("null or zero must never be available to mean 'unbounded'");
    }

    [Fact]
    public void ACapabilityMustCarryAnAlgorithmExactlyWhereOneApplies()
    {
        FluentActions.Invoking(() => new KeyStoreCapability(KeyType.Ed25519, KeyStoreOperation.Sign, null, 1024))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreCapability(KeyType.Ed25519, KeyStoreOperation.KeyAgreement, null, 1024))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreCapability(KeyType.Ed25519, KeyStoreOperation.BbsSign, null, 1024))
            .Should().Throw<ArgumentException>();

        FluentActions.Invoking(() => new KeyStoreCapability(
                KeyType.Ed25519, KeyStoreOperation.Generate, KeyStoreAlgorithms.Ed25519, 1024))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreCapability(
                KeyType.Ed25519, KeyStoreOperation.Import, KeyStoreAlgorithms.Ed25519, 1024))
            .Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ACapabilityRejectsUndefinedEnumValues()
    {
        FluentActions.Invoking(() => new KeyStoreCapability((KeyType)42, KeyStoreOperation.Generate, null, 1))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreCapability(KeyType.Ed25519, (KeyStoreOperation)42, null, 1))
            .Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ACapabilitySetRejectsMalformedContents()
    {
        var valid = new KeyStoreCapability(KeyType.Ed25519, KeyStoreOperation.Sign, KeyStoreAlgorithms.Ed25519, 1024);

        FluentActions.Invoking(() => new KeyStoreCapabilitySet("", [valid]))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreCapabilitySet("rev", null!))
            .Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => new KeyStoreCapabilitySet("rev", [valid, null!]))
            .Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => new KeyStoreCapabilitySet("rev", [valid, valid]))
            .Should().Throw<ArgumentException>("a store that advertises the same tuple twice is describing nothing");
    }

    [Fact]
    public void AnEmptyCapabilitySetIsRepresentableButMeansSomethingElse()
    {
        // Constructible — the contract's rule is that a store must never *report* an outage as
        // an empty set, which is a store obligation, not a type-level one.
        FluentActions.Invoking(() => new KeyStoreCapabilitySet("rev", [])).Should().NotThrow();
    }

    // ---------------------------------------------------------- disposal

    [Fact]
    public async Task ADisposedStore_RefusesEveryMember()
    {
        var store = CapableStoreTestSupport.NewStore();
        var (alias, instanceId) = await store.SeedAsync("k", KeyType.P256);
        store.Dispose();

        await FluentActions.Awaiting(() => store.GetCapabilitiesAsync()).Should().ThrowAsync<ObjectDisposedException>();
        await FluentActions.Awaiting(() => store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k2", KeyType.P256))).Should().ThrowAsync<ObjectDisposedException>();
        await FluentActions.Awaiting(() => store.SignAsync(
            new KeySignRequest(alias, instanceId, KeyStoreAlgorithms.Es256P1363, Data))).Should().ThrowAsync<ObjectDisposedException>();
        await FluentActions.Awaiting(() => store.GetInfoAsync(alias, instanceId)).Should().ThrowAsync<ObjectDisposedException>();
        await FluentActions.Awaiting(() => store.ListAsync()).Should().ThrowAsync<ObjectDisposedException>();
        await FluentActions.Awaiting(() => store.GetMutationOutcomeAsync(
            KeyMutationKind.Generate, CapableStoreTestSupport.NewOperationId())).Should().ThrowAsync<ObjectDisposedException>();

        store.Invoking(s => s.Dispose()).Should().NotThrow("disposal is idempotent");
    }

    [Fact]
    public void AStoreRejectsMalformedConstructionArguments()
    {
        using var backend = new InMemoryKeyStoreBackend();

        FluentActions.Invoking(() => new CapableInMemoryKeyStore(null!, CapableStoreTestSupport.CryptoProvider))
            .Should().Throw<ArgumentNullException>().WithParameterName("keyGenerator");
        FluentActions.Invoking(() => new CapableInMemoryKeyStore(CapableStoreTestSupport.KeyGenerator, null!))
            .Should().Throw<ArgumentNullException>().WithParameterName("cryptoProvider");
        FluentActions.Invoking(() => new CapableInMemoryKeyStore(
                null!, new KeyStoreNamespaceId("ns"), CapableStoreTestSupport.KeyGenerator, CapableStoreTestSupport.CryptoProvider))
            .Should().Throw<ArgumentNullException>().WithParameterName("backend");
        FluentActions.Invoking(() => new CapableInMemoryKeyStore(
                backend, default, CapableStoreTestSupport.KeyGenerator, CapableStoreTestSupport.CryptoProvider))
            .Should().Throw<ArgumentException>().WithParameterName("namespaceId");
    }
}
