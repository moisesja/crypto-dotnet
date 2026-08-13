using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Issue #26 rule 3 — instance identity is immutable and never reused. This generalizes to the
/// whole custody surface the alias-rebinding defense that <see cref="KeyStoreSigner"/> can only
/// apply on the recoverable path (issue #21), where a signature happens to encode its own signer.
/// </summary>
public class KeyInstanceIdentityTests
{
    [Fact]
    public async Task RecreatingAnAlias_MintsADifferentInstanceId()
    {
        using var store = CapableStoreTestSupport.NewStore();

        var first = await store.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.P256));
        await store.DeleteAsync(new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "k", first.InstanceId));
        var second = await store.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.P256));

        second.InstanceId.Should().NotBe(first.InstanceId);
        second.Info.PublicKey.Should().NotEqual(first.Info.PublicKey, "a re-created alias holds a genuinely different key");
    }

    [Fact]
    public async Task StaleInstanceId_FailsSigning_RatherThanSigningWithTheRebindingKey()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var stale = (await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.P256))).InstanceId;

        await store.DeleteAsync(new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "k", stale));
        var current = await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.P256));

        var act = () => store.SignAsync(new KeySignRequest("k", stale, KeyStoreAlgorithms.Es256P1363, "x"u8.ToArray()));
        await act.Should().ThrowAsync<KeyNotFoundException>();

        // The alias still works for whoever holds the current instance — the guard rejects the
        // stale reference, it does not brick the alias.
        var signature = await store.SignAsync(
            new KeySignRequest("k", current.InstanceId, KeyStoreAlgorithms.Es256P1363, "x"u8.ToArray()));
        signature.Should().HaveCount(64);
    }

    [Fact]
    public async Task StaleInstanceId_FailsKeyAgreement()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var stale = (await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.X25519))).InstanceId;

        await store.DeleteAsync(new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "k", stale));
        await store.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.X25519));

        using var peer = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.X25519);
        var act = () => store.DeriveSharedSecretAsync(
            new KeyAgreementRequest("k", stale, KeyStoreAlgorithms.EcdhX25519, peer.PublicKey));

        await act.Should().ThrowAsync<KeyNotFoundException>();
    }

    [Fact]
    public async Task StaleInstanceId_MakesGetInfoReturnNull()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var stale = (await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519))).InstanceId;

        await store.DeleteAsync(new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "k", stale));
        var current = await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        (await store.GetInfoAsync("k", stale)).Should().BeNull();
        (await store.GetInfoAsync("k", current.InstanceId)).Should().NotBeNull();
    }

    [Fact]
    public async Task DeleteWithAStaleInstanceId_DestroysNothing()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var stale = (await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519))).InstanceId;

        await store.DeleteAsync(new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "k", stale));
        var current = await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        var result = await store.DeleteAsync(new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "k", stale));

        result.Deleted.Should().BeFalse("a stale reference must never destroy the key that replaced it");
        (await store.GetInfoAsync("k", current.InstanceId)).Should().NotBeNull();
    }

    [Fact]
    public async Task InstanceIds_AreNeverReusedAcrossTheBackendLifetime()
    {
        using var backend = new InMemoryKeyStoreBackend();
        using var store = CapableStoreTestSupport.NewStore(backend, "ns");

        var seen = new HashSet<KeyInstanceId>();
        for (var i = 0; i < 200; i++)
        {
            var created = await store.GenerateAsync(
                new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "reused-alias", KeyType.Ed25519));
            seen.Add(created.InstanceId).Should().BeTrue($"instance id {created.InstanceId.Value} was minted twice");

            await store.DeleteAsync(new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "reused-alias", created.InstanceId));
        }

        seen.Should().HaveCount(200);
    }

    [Fact]
    public async Task StoredKeyInfo_CarriesTheInstanceId_OnEveryCapablePath()
    {
        using var store = CapableStoreTestSupport.NewStore();

        var created = await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        created.Info.InstanceId.Should().Be(created.InstanceId);
        (await store.GetInfoAsync("k", created.InstanceId))!.InstanceId.Should().Be(created.InstanceId);
        (await store.GetInfoAsync("k"))!.InstanceId.Should().Be(created.InstanceId);
    }

    [Fact]
    public void LegacyStoredKeyInfo_LeavesTheInstanceIdNull()
    {
        var info = new StoredKeyInfo { Alias = "k", KeyType = KeyType.Ed25519, PublicKey = new byte[32] };

        info.InstanceId.Should().BeNull("adding the property must not change any pre-existing path");
    }

    [Fact]
    public void StoredKeyInfo_Equality_DistinguishesInstances()
    {
        var publicKey = new byte[32];
        var a = new StoredKeyInfo { Alias = "k", KeyType = KeyType.Ed25519, PublicKey = publicKey, InstanceId = new KeyInstanceId("one") };
        var b = a with { InstanceId = new KeyInstanceId("two") };
        var c = a with { };

        a.Should().NotBe(b);
        a.Should().Be(c);
        a.GetHashCode().Should().Be(c.GetHashCode());
    }
}
