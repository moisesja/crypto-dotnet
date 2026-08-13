using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Issue #26 rule 4 — namespace scoping is least-privilege, and a contract property rather than
/// an alias-prefix naming convention. Every test here puts two stores over <em>one</em> backend:
/// over two separate dictionaries the claim would be vacuously true.
/// </summary>
public class NamespaceIsolationTests
{
    private readonly InMemoryKeyStoreBackend _backend = new();

    [Fact]
    public async Task ANeighbourNamespace_CannotSeeTheKey()
    {
        using var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        using var tenantB = CapableStoreTestSupport.NewStore(_backend, "tenant-b");

        var created = await tenantA.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "shared-name", KeyType.Ed25519));

        (await tenantB.GetInfoAsync("shared-name", created.InstanceId)).Should().BeNull();
        (await tenantB.GetInfoAsync("shared-name")).Should().BeNull();
        (await tenantB.ListAsync()).Should().BeEmpty();
        (await tenantA.ListAsync()).Should().Equal("shared-name");
    }

    [Fact]
    public async Task ANeighbourNamespace_CannotSignWithTheKey()
    {
        using var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        using var tenantB = CapableStoreTestSupport.NewStore(_backend, "tenant-b");

        var created = await tenantA.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.P256));

        var capable = () => tenantB.SignAsync(
            new KeySignRequest("k", created.InstanceId, KeyStoreAlgorithms.Es256P1363, "x"u8.ToArray()));
        await capable.Should().ThrowAsync<KeyNotFoundException>();

        var legacy = () => tenantB.SignAsync("k", "x"u8.ToArray());
        await legacy.Should().ThrowAsync<KeyNotFoundException>("the inherited members are scoped too");
    }

    [Fact]
    public async Task ANeighbourNamespace_CannotAgreeWithTheKey()
    {
        using var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        using var tenantB = CapableStoreTestSupport.NewStore(_backend, "tenant-b");

        var created = await tenantA.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.X25519));
        using var peer = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.X25519);

        var capable = () => tenantB.DeriveSharedSecretAsync(
            new KeyAgreementRequest("k", created.InstanceId, KeyStoreAlgorithms.EcdhX25519, peer.PublicKey));
        await capable.Should().ThrowAsync<KeyNotFoundException>();

        var legacy = () => tenantB.DeriveSharedSecretAsync("k", peer.PublicKey);
        await legacy.Should().ThrowAsync<KeyNotFoundException>();
    }

    [Fact]
    public async Task ANeighbourNamespace_CannotDeleteTheKey()
    {
        using var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        using var tenantB = CapableStoreTestSupport.NewStore(_backend, "tenant-b");

        var created = await tenantA.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        var capable = await tenantB.DeleteAsync(
            new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "k", created.InstanceId));
        capable.Deleted.Should().BeFalse();

        (await tenantB.DeleteAsync("k")).Should().BeFalse();
        (await tenantA.GetInfoAsync("k", created.InstanceId)).Should().NotBeNull("the key survived both attempts");
    }

    [Fact]
    public async Task ANeighbourNamespace_CannotCreateASignerForTheKey()
    {
        using var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        using var tenantB = CapableStoreTestSupport.NewStore(_backend, "tenant-b");

        await tenantA.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        var act = () => tenantB.CreateSignerAsync("k");
        await act.Should().ThrowAsync<KeyNotFoundException>();
    }

    [Fact]
    public async Task TheSameAliasInTwoNamespaces_AreTwoIndependentKeys()
    {
        using var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        using var tenantB = CapableStoreTestSupport.NewStore(_backend, "tenant-b");

        var a = await tenantA.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));
        var b = await tenantB.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        b.InstanceId.Should().NotBe(a.InstanceId);
        b.Info.PublicKey.Should().NotEqual(a.Info.PublicKey);
    }

    [Fact]
    public async Task TheSameOperationId_DoesNotCollideAcrossNamespaces()
    {
        using var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        using var tenantB = CapableStoreTestSupport.NewStore(_backend, "tenant-b");
        var operationId = CapableStoreTestSupport.NewOperationId();

        var a = await tenantA.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519));
        var b = await tenantB.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519));

        a.Replayed.Should().BeFalse();
        b.Replayed.Should().BeFalse("mutation identity includes the namespace");
        b.InstanceId.Should().NotBe(a.InstanceId);

        (await tenantB.GetMutationOutcomeAsync(KeyMutationKind.Generate, operationId))
            .Should().BeOfType<KeyGeneratedOutcome>()
            .Which.InstanceId.Should().Be(b.InstanceId, "each namespace reads its own receipt");
    }

    [Fact]
    public async Task DisposingOneStore_LeavesTheOtherNamespaceWorking()
    {
        var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        using var tenantB = CapableStoreTestSupport.NewStore(_backend, "tenant-b");

        var b = await tenantB.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));
        tenantA.Dispose();

        (await tenantB.GetInfoAsync("k", b.InstanceId)).Should().NotBeNull(
            "a store handed a shared backend must not dispose state it does not own");
    }

    [Fact]
    public async Task DisposingTheBackend_StopsEveryStoreOverIt()
    {
        using var tenantA = CapableStoreTestSupport.NewStore(_backend, "tenant-a");
        await tenantA.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        _backend.Dispose();

        var act = () => tenantA.ListAsync();
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }
}
