using FluentAssertions;
using NetCrypto;

namespace NetCrypto.ExternalStore.Tests;

/// <summary>
/// Issue #28's acceptance sketch, executed from an assembly with no <c>InternalsVisibleTo</c>
/// grant. Every call below is one a third-party custody provider makes; that this file compiles
/// is itself the primary assertion.
/// </summary>
public class ExternalStoreImportTests
{
    private static readonly DefaultKeyGenerator Generator = new();

    private static WrappingExternalKeyStore NewStore() =>
        new([0x5A, 0xC3, 0x11, 0xF0, 0x9E, 0x24, 0x7B, 0x86]);

    private static KeyOperationId NewOperationId() => new(Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task AnExternalStore_ReadsTheMaterialExactlyOnce_AndTheTrueSecretCrosses()
    {
        var store = NewStore();
        using var source = Generator.Generate(KeyType.Ed25519);
        var expectedPrivateKey = source.PrivateKey;
        var expectedPublicKey = source.PublicKey;
        var material = TransferableKeyMaterial.FromKeyPair(source);

        var result = await store.ImportAsync(new KeyImportRequest(NewOperationId(), "byok", material));

        store.ReaderEntries.Should().Be(1, "the acceptance path reads the material exactly once");
        result.Info.PublicKey.Should().Equal(expectedPublicKey);
        store.Unwrap("byok").Should().Equal(
            expectedPrivateKey,
            "the store must receive the real secret — a mid-read zeroization would hand it zeros");
    }

    [Fact]
    public async Task AfterAnExternalStoreAccepts_TheMaterialIsLatchedUnreadable()
    {
        var store = NewStore();
        using var source = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(source);

        await store.ImportAsync(new KeyImportRequest(NewOperationId(), "byok", material));

        material.IsConsumed.Should().BeTrue();
        material.Invoking(m => m.PublicKey).Should().Throw<ObjectDisposedException>();
        material.Invoking(m => m.KeyType).Should().Throw<ObjectDisposedException>();
        material.Invoking(m => m.Consume((_, _, _) => 0)).Should().Throw<ObjectDisposedException>(
            "a second read is exactly what the type exists to prevent");
    }

    [Fact]
    public void DiscardFromAnExternalAssembly_DestroysAnUnreadOwner()
    {
        using var source = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(source);

        material.Discard();

        material.IsConsumed.Should().BeTrue();
        material.Invoking(m => m.PublicKey).Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task AReplayedImport_DestroysTheMaterialWithoutReadingIt()
    {
        var store = NewStore();
        using var source = Generator.Generate(KeyType.Ed25519);

        await store.ImportAsync(new KeyImportRequest(NewOperationId(), "byok", TransferableKeyMaterial.FromKeyPair(source)));
        store.ReaderEntries.Should().Be(1);

        var retry = TransferableKeyMaterial.FromKeyPair(source);
        var replay = await store.ImportAsync(new KeyImportRequest(NewOperationId(), "byok", retry));

        replay.Replayed.Should().BeTrue();
        store.ReaderEntries.Should().Be(1, "a recognized replay never re-reads private material");
        retry.IsConsumed.Should().BeTrue("but it is not left lying around with the caller either");
    }

    [Fact]
    public void AFailingReaderStillSpendsTheMaterial()
    {
        using var source = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(source);

        material.Invoking(m => m.Consume<int>((_, _, _) => throw new InvalidOperationException("wrap failed")))
            .Should().Throw<InvalidOperationException>();

        material.IsConsumed.Should().BeTrue(
            "material exposed to a store is spent whether or not the store's ingestion completed");
    }

    [Fact]
    public void ANullReader_IsAParameterFault()
    {
        using var source = Generator.Generate(KeyType.Ed25519);
        using var material = TransferableKeyMaterial.FromKeyPair(source);

        material.Invoking(m => m.Consume<int>(null!))
            .Should().Throw<ArgumentNullException>().WithParameterName("read");
    }
}
