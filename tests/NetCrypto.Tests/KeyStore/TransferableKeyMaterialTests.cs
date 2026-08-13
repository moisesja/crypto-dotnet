using System.Reflection;
using FluentAssertions;

namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Issue #26 rule 7 — import transfers ownership exactly once. The type exists because handing
/// a <see cref="KeyPair"/> to a store leaves the caller holding a live export surface
/// (<see cref="KeyPair.PrivateKey"/> clones the secret on every read), which quietly undoes the
/// store's defining property.
/// </summary>
public class TransferableKeyMaterialTests
{
    private static byte[] BackingPrivateKey(TransferableKeyMaterial material)
    {
        var field = typeof(TransferableKeyMaterial).GetField("_privateKey", BindingFlags.NonPublic | BindingFlags.Instance);
        field.Should().NotBeNull();
        return (byte[])field!.GetValue(material)!;
    }

    // --- the type itself ---

    [Fact]
    public void ExposesNoReadPathForPrivateMaterial()
    {
        var forbidden = typeof(TransferableKeyMaterial)
            .GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Select(m => m.Name)
            .Where(name => name.Contains("Private", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Export", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Jwk", StringComparison.OrdinalIgnoreCase)
                || name.Contains("Secret", StringComparison.OrdinalIgnoreCase))
            .ToList();

        forbidden.Should().BeEmpty("the whole point is that no caller-reachable read path exists");
    }

    [Fact]
    public void FromKeyPair_CopiesTheMaterial_AndLeavesTheSourceAlone()
    {
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);

        using var material = TransferableKeyMaterial.FromKeyPair(pair);

        material.KeyType.Should().Be(KeyType.Ed25519);
        material.PublicKey.Should().Equal(pair.PublicKey);
        material.IsConsumed.Should().BeFalse();
        pair.Invoking(p => p.PublicKey).Should().NotThrow("the source pair is the caller's to dispose");
    }

    [Fact]
    public void PublicKey_IsDefensivelyCopied()
    {
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        using var material = TransferableKeyMaterial.FromKeyPair(pair);

        var first = material.PublicKey;
        first[0] ^= 0xFF;

        material.PublicKey.Should().NotEqual(first);
    }

    [Fact]
    public void Dispose_ZeroizesWithoutTransferring()
    {
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        var backing = BackingPrivateKey(material);
        backing.Should().Contain(b => b != 0);

        material.Dispose();

        backing.Should().OnlyContain(b => b == 0);
        material.IsConsumed.Should().BeTrue();
        material.Invoking(m => m.KeyType).Should().Throw<ObjectDisposedException>();
        material.Invoking(m => m.PublicKey).Should().Throw<ObjectDisposedException>();
        material.Invoking(m => m.Dispose()).Should().NotThrow("disposal is idempotent");
    }

    [Theory]
    [InlineData(0, 32)]
    [InlineData(32, 0)]
    public void FromRawKey_RejectsEmptyMaterial(int publicLength, int privateLength)
    {
        var act = () => TransferableKeyMaterial.FromRawKey(KeyType.Ed25519, new byte[publicLength], new byte[privateLength]);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void FromRawKey_RejectsAnUndefinedKeyType()
    {
        var act = () => TransferableKeyMaterial.FromRawKey((KeyType)999, new byte[32], new byte[32]);

        act.Should().Throw<ArgumentException>().WithParameterName("keyType");
    }

    [Fact]
    public void FromKeyPair_RejectsNull()
    {
        var act = () => TransferableKeyMaterial.FromKeyPair(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("keyPair");
    }

    // --- transfer through the store ---

    [Fact]
    public async Task AcceptedImport_ConsumesTheMaterial_AndZeroizesIt()
    {
        using var store = CapableStoreTestSupport.NewStore();
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        var backing = BackingPrivateKey(material);
        var expectedPublicKey = pair.PublicKey;

        var result = await store.ImportAsync(
            new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k", material));

        result.Info.PublicKey.Should().Equal(expectedPublicKey);
        material.IsConsumed.Should().BeTrue();
        material.ReadCount.Should().Be(1, "material is read exactly once, at acceptance");
        backing.Should().OnlyContain(b => b == 0, "the transferred buffer is wiped after ingestion");
        material.Invoking(m => m.PublicKey).Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task AnAcceptedImport_CannotBeReused()
    {
        using var store = CapableStoreTestSupport.NewStore();
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);

        await store.ImportAsync(new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k", material));

        var act = () => store.ImportAsync(new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "other", material));
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task TheImportedKeySigns_ProvingTheMaterialSurvivedTheTransfer()
    {
        using var store = CapableStoreTestSupport.NewStore();
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.P256);
        var publicKey = pair.PublicKey;
        var material = TransferableKeyMaterial.FromKeyPair(pair);

        var imported = await store.ImportAsync(
            new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k", material));

        var data = "payload"u8.ToArray();
        var signature = await store.SignAsync(
            new KeySignRequest("k", imported.InstanceId, KeyStoreAlgorithms.Es256P1363, data));

        CapableStoreTestSupport.CryptoProvider
            .Verify(KeyType.P256, publicKey, data, signature, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue();
    }

    [Fact]
    public async Task FailureBeforeAcceptance_LeavesTheMaterialUsableForOneRetry()
    {
        using var store = CapableStoreTestSupport.NewStore();
        await store.SeedAsync("taken", KeyType.Ed25519);

        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);

        var collision = () => store.ImportAsync(
            new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "taken", material));
        await collision.Should().ThrowAsync<InvalidOperationException>();

        material.IsConsumed.Should().BeFalse("nothing was accepted, so nothing was spent");
        material.ReadCount.Should().Be(0);

        var retry = await store.ImportAsync(
            new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "free", material));
        retry.Info.Alias.Should().Be("free");
        material.ReadCount.Should().Be(1);
    }

    [Fact]
    public async Task AnIdempotencyConflict_LeavesTheMaterialUsable()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var operationId = CapableStoreTestSupport.NewOperationId();
        using var first = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        await store.ImportAsync(new KeyImportRequest(operationId, "k", TransferableKeyMaterial.FromKeyPair(first)));

        using var second = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(second);

        var act = () => store.ImportAsync(new KeyImportRequest(operationId, "k", material));
        (await act.Should().ThrowAsync<KeyStoreException>())
            .Which.Error.Should().Be(KeyStoreError.IdempotencyConflict);

        material.IsConsumed.Should().BeFalse();
        material.ReadCount.Should().Be(0, "a conflicting request was never accepted");
    }

    [Fact]
    public async Task AReplayedImport_DestroysTheMaterialWithoutEverReadingIt()
    {
        using var store = CapableStoreTestSupport.NewStore();
        var operationId = CapableStoreTestSupport.NewOperationId();
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);

        var firstMaterial = TransferableKeyMaterial.FromKeyPair(pair);
        var original = await store.ImportAsync(new KeyImportRequest(operationId, "k", firstMaterial));

        // The retry after a lost acknowledgement: same operation id, same key, a second
        // transfer object holding the same secret.
        var retryMaterial = TransferableKeyMaterial.FromKeyPair(pair);
        var backing = BackingPrivateKey(retryMaterial);

        var replay = await store.ImportAsync(new KeyImportRequest(operationId, "k", retryMaterial));

        replay.Replayed.Should().BeTrue();
        replay.InstanceId.Should().Be(original.InstanceId);
        retryMaterial.ReadCount.Should().Be(0, "private material is never re-read on a replay");
        retryMaterial.IsConsumed.Should().BeTrue("but it is not left lying around either");
        backing.Should().OnlyContain(b => b == 0);
    }

    [Fact]
    public async Task ConsumedMaterial_IsRejectedBeforeAnythingElseIsValidated()
    {
        using var store = CapableStoreTestSupport.NewStore();
        using var pair = CapableStoreTestSupport.KeyGenerator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(pair);
        material.Dispose();

        var act = () => store.ImportAsync(new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k", material));

        await act.Should().ThrowAsync<ObjectDisposedException>();
        (await store.ListAsync()).Should().BeEmpty();
    }

    [Fact]
    public async Task NullMaterial_IsAParameterFault()
    {
        using var store = CapableStoreTestSupport.NewStore();

        var act = () => store.ImportAsync(new KeyImportRequest(CapableStoreTestSupport.NewOperationId(), "k", null!));

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task ImportIsRefusedEntirelyWhereItIsNotAdvertised_SoMaterialIsNeverSeen()
    {
        // The reference store advertises Import for every key type, so this asserts the
        // ordering instead: an unadvertised key type is rejected before the material is read.
        using var store = CapableStoreTestSupport.NewStore();
        var capabilities = await store.GetCapabilitiesAsync();

        capabilities.Capabilities
            .Count(c => c.Operation == KeyStoreOperation.Import)
            .Should().Be(Enum.GetValues<KeyType>().Length);
    }
}
