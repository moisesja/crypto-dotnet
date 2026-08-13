using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Issue #26 rule 5 — mutations are durably idempotent under
/// <c>(namespace, kind, operation id)</c>, with a canonical request fingerprint separating an
/// honest retry from a different request reusing the key.
/// </summary>
public class IdempotencyTests
{
    private readonly InMemoryKeyStoreBackend _backend = new();

    [Fact]
    public async Task ReplayingAGenerate_ReturnsTheOriginalResult_AndCreatesNothingNew()
    {
        using var store = CapableStoreTestSupport.NewStore(_backend, "ns");
        var request = new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.P256);

        var first = await store.GenerateAsync(request);
        var second = await store.GenerateAsync(request);

        first.Replayed.Should().BeFalse();
        second.Replayed.Should().BeTrue();
        second.InstanceId.Should().Be(first.InstanceId);
        second.Info.Should().Be(first.Info);
        (await store.ListAsync()).Should().ContainSingle("a retry must not double-create").Which.Should().Be("k");
    }

    [Fact]
    public async Task ReusingAnOperationIdForADifferentRequest_IsAConflict()
    {
        using var store = CapableStoreTestSupport.NewStore(_backend, "ns");
        var operationId = CapableStoreTestSupport.NewOperationId();
        await store.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.P256));

        var differentAlias = () => store.GenerateAsync(new KeyGenerateRequest(operationId, "other", KeyType.P256));
        (await differentAlias.Should().ThrowAsync<KeyStoreException>())
            .Which.Error.Should().Be(KeyStoreError.IdempotencyConflict);

        var differentKeyType = () => store.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519));
        (await differentKeyType.Should().ThrowAsync<KeyStoreException>())
            .Which.Error.Should().Be(KeyStoreError.IdempotencyConflict);

        (await store.ListAsync()).Should().Equal("k");
    }

    [Fact]
    public async Task TheFingerprintIsUnambiguous_AcrossFieldBoundaries()
    {
        using var store = CapableStoreTestSupport.NewStore(_backend, "ns");
        var operationId = CapableStoreTestSupport.NewOperationId();

        // "a|Ed25519" vs "a" + "|Ed25519": a delimiter-joined fingerprint would let these two
        // requests collide and silently replay each other. Length-prefixing is what prevents it.
        await store.GenerateAsync(new KeyGenerateRequest(operationId, "a|Ed25519", KeyType.Ed25519));

        var act = () => store.GenerateAsync(new KeyGenerateRequest(operationId, "a", KeyType.Ed25519));

        (await act.Should().ThrowAsync<KeyStoreException>())
            .Which.Error.Should().Be(KeyStoreError.IdempotencyConflict);
    }

    [Fact]
    public async Task ReplayingADelete_ReturnsTheOriginalOutcome()
    {
        using var store = CapableStoreTestSupport.NewStore(_backend, "ns");
        var created = await store.GenerateAsync(
            new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));
        var request = new KeyDeleteRequest(CapableStoreTestSupport.NewOperationId(), "k", created.InstanceId);

        var first = await store.DeleteAsync(request);
        var second = await store.DeleteAsync(request);

        first.Should().BeEquivalentTo(new KeyDeleteResult(Deleted: true, Replayed: false));
        second.Should().BeEquivalentTo(new KeyDeleteResult(Deleted: true, Replayed: true),
            "the replay reports the original outcome, not 'nothing to delete'");
    }

    [Fact]
    public async Task TheLedgerOutlivesTheStoreInstanceThatWroteIt()
    {
        var operationId = CapableStoreTestSupport.NewOperationId();
        KeyMutationResult created;

        using (var before = CapableStoreTestSupport.NewStore(_backend, "ns"))
            created = await before.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519));

        // A new store over the same backend is this library's stand-in for a process restart.
        using var after = CapableStoreTestSupport.NewStore(_backend, "ns");

        var replay = await after.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519));
        replay.Replayed.Should().BeTrue();
        replay.InstanceId.Should().Be(created.InstanceId);

        var receipt = await after.GetMutationOutcomeAsync(KeyMutationKind.Generate, operationId);
        receipt.Should().BeOfType<KeyGeneratedOutcome>().Which.InstanceId.Should().Be(created.InstanceId);
    }

    [Fact]
    public async Task TheOutcomeReader_ReturnsTheReceiptForEachKind()
    {
        using var store = CapableStoreTestSupport.NewStore(_backend, "ns");
        var generateId = CapableStoreTestSupport.NewOperationId();
        var deleteId = CapableStoreTestSupport.NewOperationId();

        var created = await store.GenerateAsync(new KeyGenerateRequest(generateId, "k", KeyType.Ed25519));
        await store.DeleteAsync(new KeyDeleteRequest(deleteId, "k", created.InstanceId));

        var generated = await store.GetMutationOutcomeAsync(KeyMutationKind.Generate, generateId);
        generated.Should().BeOfType<KeyGeneratedOutcome>();
        generated!.Kind.Should().Be(KeyMutationKind.Generate);
        generated.OperationId.Should().Be(generateId);
        generated.RecordedAt.Should().BeAfter(DateTimeOffset.UnixEpoch);

        var deletion = await store.GetMutationOutcomeAsync(KeyMutationKind.Delete, deleteId);
        deletion.Should().BeOfType<KeyDeletionOutcome>().Which.Deleted.Should().BeTrue();
        deletion!.Kind.Should().Be(KeyMutationKind.Delete);
    }

    [Fact]
    public async Task TheOutcomeReader_IsSideEffectFree_AndReturnsNullForAnUnknownId()
    {
        using var store = CapableStoreTestSupport.NewStore(_backend, "ns");
        await store.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));
        var before = await store.ListAsync();

        var unknown = await store.GetMutationOutcomeAsync(KeyMutationKind.Generate, CapableStoreTestSupport.NewOperationId());

        unknown.Should().BeNull();
        (await store.ListAsync()).Should().Equal(before);
    }

    [Fact]
    public async Task TheSameOperationId_AddressesADifferentOperationPerKind()
    {
        using var store = CapableStoreTestSupport.NewStore(_backend, "ns");
        var operationId = CapableStoreTestSupport.NewOperationId();

        var created = await store.GenerateAsync(new KeyGenerateRequest(operationId, "k", KeyType.Ed25519));
        var deleted = await store.DeleteAsync(new KeyDeleteRequest(operationId, "k", created.InstanceId));

        deleted.Replayed.Should().BeFalse("kind is part of mutation identity");
        deleted.Deleted.Should().BeTrue();
    }

    [Fact]
    public async Task ADuplicateAlias_UnderAFreshOperationId_IsStillRejected()
    {
        using var store = CapableStoreTestSupport.NewStore(_backend, "ns");
        await store.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        var act = () => store.GenerateAsync(new KeyGenerateRequest(CapableStoreTestSupport.NewOperationId(), "k", KeyType.Ed25519));

        await act.Should().ThrowAsync<InvalidOperationException>(
            "idempotency is about retrying one operation, not about making collisions silent");
    }
}
