using FluentAssertions;
using NetCrypto;

namespace NetCrypto.ExternalStore.Tests;

/// <summary>
/// FR-7b rule 14 (a callback must not re-enter) applied to the reader delegate that #28 made
/// public. <c>Monitor</c> is reentrant and <c>Consume</c>'s latch only closes on the way out, so
/// an untrusted reader that calls back into the material it is reading would otherwise take a
/// second read <em>and</em> zeroize the pinned buffers the outer read is still borrowing —
/// leaving the accepting store to ingest an all-zero key. While <c>Consume</c> was internal the
/// only caller was the in-assembly store; publishing it put an arbitrary delegate in that seat.
/// </summary>
public class ConsumeReentrancyTests
{
    private static readonly DefaultKeyGenerator Generator = new();

    [Fact]
    public void AReaderThatReEntersConsume_IsRefused()
    {
        using var source = Generator.Generate(KeyType.Ed25519);
        var material = TransferableKeyMaterial.FromKeyPair(source);

        Exception? nested = null;
        material.Consume((_, _, _) =>
        {
            nested = Record.Exception(() => material.Consume((_, _, _) => 0));
            return 0;
        });

        nested.Should().BeOfType<InvalidOperationException>(
            "a nested read would break read-exactly-once and blank the outer read's buffers");
    }

    [Fact]
    public void AReaderThatReEntersConsume_DoesNotCorruptTheOuterRead()
    {
        using var source = Generator.Generate(KeyType.Ed25519);
        var expectedPrivateKey = source.PrivateKey;
        var material = TransferableKeyMaterial.FromKeyPair(source);

        var observed = material.Consume((_, _, privateKey) =>
        {
            // The attack: get the buffers wiped mid-read, then let the store commit what it now
            // sees. Whatever this nested call does, the bytes below must still be the real key.
            _ = Record.Exception(() => material.Consume((_, _, _) => 0));
            return privateKey.ToArray();
        });

        observed.Should().Equal(expectedPrivateKey,
            "the outer read must never observe a buffer a nested call zeroized under it");
    }

    [Fact]
    public void AReaderThatDisposesTheMaterial_DoesNotCorruptTheOuterRead()
    {
        using var source = Generator.Generate(KeyType.Ed25519);
        var expectedPrivateKey = source.PrivateKey;
        var material = TransferableKeyMaterial.FromKeyPair(source);

        var observed = material.Consume((_, _, privateKey) =>
        {
            // Dispose stays idempotent and never throws, so it cannot be refused the way a
            // nested Consume is; instead it defers to the wipe this call already guarantees.
            material.Dispose();
            return privateKey.ToArray();
        });

        observed.Should().Equal(expectedPrivateKey);
        material.IsConsumed.Should().BeTrue("the deferred wipe still happens on the way out");
        material.Invoking(m => m.PublicKey).Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void AReaderThatDiscardsTheMaterial_DoesNotCorruptTheOuterRead()
    {
        using var source = Generator.Generate(KeyType.Ed25519);
        var expectedPrivateKey = source.PrivateKey;
        var material = TransferableKeyMaterial.FromKeyPair(source);

        var observed = material.Consume((_, _, privateKey) =>
        {
            material.Discard();
            return privateKey.ToArray();
        });

        observed.Should().Equal(expectedPrivateKey);
        material.IsConsumed.Should().BeTrue();
    }

    [Fact]
    public void ReadingPublicMetadataFromInsideAReader_StillWorks()
    {
        using var source = Generator.Generate(KeyType.Ed25519);
        var expectedPublicKey = source.PublicKey;
        var material = TransferableKeyMaterial.FromKeyPair(source);

        var (keyType, publicKey) = material.Consume<(KeyType, byte[])>((_, _, _) =>
            (material.KeyType, material.PublicKey));

        keyType.Should().Be(KeyType.Ed25519, "only a nested Consume is refused, not metadata");
        publicKey.Should().Equal(expectedPublicKey);
    }
}
