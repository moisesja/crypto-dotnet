using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.NonFunctional;

/// <summary>
/// Regression tests for the confirmed findings of the adversarial review (2026-06-10).
/// Each guards a specific NFR-3 / FR-5 defect that the review reproduced.
/// The null-guard and length-guard tests need no native library (they fail fast before any
/// crypto work), so they run on every CI leg; the BBS proof-size test requires the FFI.
/// </summary>
public class ReviewRegressionTests
{
    private static readonly DefaultCryptoProvider Provider = new();
    private static readonly DefaultKeyGenerator KeyGen = new();

    // ── Finding #1 — secp256k1 sub-32-byte keys formerly crashed with IndexOutOfRangeException ──

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void SignSecp256k1_NonStandardKeyLength_ThrowsArgumentException(int length)
    {
        var act = () => Provider.Sign(KeyType.Secp256k1, new byte[length], [1, 2, 3]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void FromPrivateKeySecp256k1_NonStandardKeyLength_ThrowsArgumentException(int length)
    {
        var act = () => KeyGen.FromPrivateKey(KeyType.Secp256k1, new byte[length]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    // ── Finding #2 — BBS ops formerly threw NullReferenceException on null message/index lists ──

    [Fact]
    public void BbsSign_NullMessages_ThrowsArgumentNullException()
    {
        var bbs = new DefaultBbsCryptoProvider();
        var act = () => bbs.Sign(new byte[32], null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("messages");
    }

    [Fact]
    public void BbsVerify_NullMessages_ThrowsArgumentNullException()
    {
        var bbs = new DefaultBbsCryptoProvider();
        var act = () => bbs.Verify(new byte[96], new byte[80], null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("messages");
    }

    [Fact]
    public void BbsDeriveProof_NullArguments_ThrowArgumentNullException()
    {
        var bbs = new DefaultBbsCryptoProvider();
        ((Action)(() => bbs.DeriveProof(new byte[96], null!, [[1]], [0], default)))
            .Should().Throw<ArgumentNullException>().WithParameterName("signature");
        ((Action)(() => bbs.DeriveProof(new byte[96], new byte[80], null!, [0], default)))
            .Should().Throw<ArgumentNullException>().WithParameterName("messages");
        ((Action)(() => bbs.DeriveProof(new byte[96], new byte[80], [[1]], null!, default)))
            .Should().Throw<ArgumentNullException>().WithParameterName("revealedIndices");
    }

    [Fact]
    public void BbsVerifyProof_NullArguments_ThrowArgumentNullException()
    {
        var bbs = new DefaultBbsCryptoProvider();
        ((Action)(() => bbs.VerifyProof(new byte[96], null!, [[1]], [0], default)))
            .Should().Throw<ArgumentNullException>().WithParameterName("proof");
        ((Action)(() => bbs.VerifyProof(new byte[96], new byte[100], null!, [0], default)))
            .Should().Throw<ArgumentNullException>().WithParameterName("revealedMessages");
        ((Action)(() => bbs.VerifyProof(new byte[96], new byte[100], [[1]], null!, default)))
            .Should().Throw<ArgumentNullException>().WithParameterName("revealedIndices");
    }

    // ── Finding #3 — DeriveProof under-allocated the proof buffer for >= 8 undisclosed messages ──
    // The 512-byte floor masked it for small reveals; large undisclosed counts threw
    // CryptographicException. Requires the native library, so it carries the NativeFFI trait.

    [Theory]
    [Trait("Category", "NativeFFI")]
    [InlineData(12)]   // undisclosed = 11 → true proof size 624 > old 528-byte allocation
    [InlineData(20)]   // undisclosed = 19
    [InlineData(40)]   // undisclosed = 39
    public void BbsDeriveProof_ManyUndisclosedMessages_RoundTrips(int messageCount)
    {
        var bbs = new DefaultBbsCryptoProvider();
        var keyPair = KeyGen.Generate(KeyType.Bls12381G2);

        var messages = new List<byte[]>();
        for (var i = 0; i < messageCount; i++)
            messages.Add(System.Text.Encoding.UTF8.GetBytes($"message-{i}"));

        var signature = bbs.Sign(keyPair.PrivateKey, messages);
        var revealed = new List<int> { 0 }; // reveal one → undisclosed = messageCount - 1
        var nonce = RandomNumberGenerator.GetBytes(16);

        var proof = bbs.DeriveProof(keyPair.PublicKey, signature, messages, revealed, nonce);
        proof.Length.Should().Be(272 + 32 * (messageCount - 1),
            "BBS BLS12-381-SHA-256 proof size is 272 + 32*undisclosed bytes (draft-10)");

        var revealedMessages = new List<byte[]> { messages[0] };
        bbs.VerifyProof(keyPair.PublicKey, proof, revealedMessages, revealed, nonce)
            .Should().BeTrue("a proof over many undisclosed messages must verify");
    }

    // ── Finding #4 — JwkConverter.ToPublicJwk silently accepted wrong-length EC points ──

    [Theory]
    [InlineData(KeyType.P256, new byte[] { 0x02, 1, 2, 3, 4, 5 })]          // 6-byte compressed
    [InlineData(KeyType.P256, new byte[] { 0x04, 1, 2 })]                    // 3-byte uncompressed
    [InlineData(KeyType.P384, new byte[] { 0x02, 1, 2, 3 })]                 // wrong compressed len
    public void ToPublicJwk_WrongLengthEcPoint_ThrowsArgumentException(KeyType keyType, byte[] badPoint)
    {
        var act = () => JwkConverter.ToPublicJwk(keyType, badPoint);
        act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
    }
}
