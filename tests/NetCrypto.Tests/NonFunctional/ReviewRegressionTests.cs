using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using NetCrypto;

namespace NetCrypto.Tests.NonFunctional;

/// <summary>
/// Regression tests for the confirmed findings of the adversarial reviews (2026-06-10 and the
/// follow-up security review 2026-06-11). Each guards a specific NFR-3 / FR-5 / contract defect
/// that a review reproduced. The null-guard and length-guard tests need no native library (they
/// fail fast before any crypto work), so they run on every CI leg; tests that exercise the BBS
/// FFI carry the NativeFFI trait.
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

    // ════════════════════════ Security review — 2026-06-11 ════════════════════════

    // ── ConcatKdf: an oversized keyDataLen formerly overflowed int → OverflowException ──

    [Fact]
    public void ConcatKdf_OversizedKeyDataLen_ThrowsArgumentOutOfRange_NotOverflow()
    {
        var act = () => ConcatKdf.DeriveKey(
            new byte[32], default, default, default, default, default, int.MaxValue);
        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("keyDataLen");
    }

    // ── KeyTypeExtensions.NormalizeToCompressed(null) formerly threw NullReferenceException ──

    [Fact]
    public void NormalizeToCompressed_NullPublicKey_ThrowsArgumentNullException()
    {
        var act = () => KeyType.P256.NormalizeToCompressed(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("publicKey");
    }

    // ── JwkConverter.ExtractPublicKey formerly leaked a raw FormatException on bad base64url ──

    [Fact]
    public void ExtractPublicKey_MalformedBase64Url_ThrowsArgumentExceptionNotFormatException()
    {
        var okp = new JsonWebKey { Kty = "OKP", Crv = "Ed25519", X = "!!!not-base64!!!" };
        ((Action)(() => JwkConverter.ExtractPublicKey(okp)))
            .Should().Throw<ArgumentException>().WithParameterName("jwk");

        var ec = new JsonWebKey { Kty = "EC", Crv = "P-256", X = "@@@bad@@@", Y = "AAAA" };
        ((Action)(() => JwkConverter.ExtractPublicKey(ec)))
            .Should().Throw<ArgumentException>().WithParameterName("jwk");
    }

    // ── JwkConverter.ExtractPublicKey formerly built a short SEC1 point from a left-trimmed X ──

    [Fact]
    public void ExtractPublicKey_LeftTrimmedEcCoordinate_PadsBackToFullWidth()
    {
        // Find a P-256 key whose X coordinate has a 0x00 most-significant byte; a base64url
        // encoder that strips leading zeros would then emit a 31-byte X for it.
        var kp = KeyGen.Generate(KeyType.P256);
        for (var i = 0; i < 100_000 && kp.PublicKey[1] != 0x00; i++)
            kp = KeyGen.Generate(KeyType.P256);
        kp.PublicKey[1].Should().Be(0x00, "the test requires a leading-zero X coordinate");

        var jwk = JwkConverter.ToPublicJwk(KeyType.P256, kp.PublicKey);
        var xFull = Base64UrlDecode(jwk.X);   // 32 bytes, xFull[0] == 0x00
        jwk.X = Base64UrlEncode(xFull[1..]);   // re-encode trimmed (31 bytes)

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(jwk);

        keyType.Should().Be(KeyType.P256);
        publicKey.Length.Should().Be(33, "the SEC1 compressed point must be padded to full field width");
        publicKey.Should().Equal(kp.PublicKey, "the padded point must round-trip to the original key");
    }

    // ── DefaultCryptoProvider.Verify formerly threw CryptographicException on an off-curve key ──

    [Theory]
    [InlineData(KeyType.P256, 32, 64)]   // 0x04 || 32-byte x || 32-byte y, P1363 sig = 64
    [InlineData(KeyType.P384, 48, 96)]
    public void Verify_OffCurvePublicKey_ReturnsFalseNotThrow(KeyType keyType, int coordLen, int sigLen)
    {
        // (x, y) = (2, 3) is not on any of these curves.
        var pk = new byte[1 + 2 * coordLen];
        pk[0] = 0x04;
        pk[coordLen] = 2;          // last byte of x
        pk[2 * coordLen] = 3;      // last byte of y
        var data = new byte[] { 1, 2, 3 };
        var sig = new byte[sigLen];

        var act = () => Provider.Verify(keyType, pk, data, sig, EcdsaSignatureFormat.IeeeP1363);
        act.Should().NotThrow("an off-curve public key is a verification failure, not an exception");
        Provider.Verify(keyType, pk, data, sig, EcdsaSignatureFormat.IeeeP1363).Should().BeFalse();
    }

    // ── InMemoryKeyStore public methods formerly threw NRE / accepted null on bad arguments ──

    [Fact]
    public async Task InMemoryKeyStore_NullKeyPair_ThrowsArgumentNullException()
    {
        var store = new InMemoryKeyStore(KeyGen, Provider);
        await ((Func<Task>)(() => store.ImportAsync("alias", null!)))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("keyPair");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task InMemoryKeyStore_NullOrEmptyAlias_ThrowsArgumentException(string? alias)
    {
        var store = new InMemoryKeyStore(KeyGen, Provider);
        await ((Func<Task>)(() => store.GenerateAsync(alias!, KeyType.Ed25519)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
        await ((Func<Task>)(() => store.SignAsync(alias!, new byte[] { 1 })))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
        await ((Func<Task>)(() => store.DeleteAsync(alias!)))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
    }

    // ── DeriveX25519FromEd25519 formerly threw a raw NSec FormatException on a wrong-length seed ──

    [Fact]
    public void DeriveX25519FromEd25519_WrongLengthPrivateKey_ThrowsArgumentException()
    {
        var bad = new KeyPair { KeyType = KeyType.Ed25519, PrivateKey = new byte[16], PublicKey = new byte[32] };
        var act = () => KeyGen.DeriveX25519FromEd25519(bad);
        act.Should().Throw<ArgumentException>().WithParameterName("ed25519KeyPair");
    }

    [Fact]
    public void DeriveX25519FromEd25519_Null_ThrowsArgumentNullException()
    {
        var act = () => KeyGen.DeriveX25519FromEd25519(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("ed25519KeyPair");
    }

    // ── DeriveX25519PublicKeyFromEd25519 formerly returned a degenerate u=0 for the y=1 map ──

    [Fact]
    public void DeriveX25519PublicKeyFromEd25519_DegenerateY1_ThrowsArgumentException()
    {
        var pk = new byte[32];
        pk[0] = 1; // y = 1 (little-endian) → (1 - y) = 0 → birational map undefined
        var act = () => KeyGen.DeriveX25519PublicKeyFromEd25519(pk);
        act.Should().Throw<ArgumentException>().WithParameterName("ed25519PublicKey");
    }

    // ── DeriveProof formerly passed an out-of-range index straight to the FFI (opaque error) ──

    [Theory]
    [Trait("Category", "NativeFFI")]
    [InlineData(-1)]
    [InlineData(3)]    // == message count
    [InlineData(99)]
    public void BbsDeriveProof_RevealedIndexOutOfRange_ThrowsArgumentOutOfRange(int badIndex)
    {
        var bbs = new DefaultBbsCryptoProvider();
        var keyPair = KeyGen.Generate(KeyType.Bls12381G2);
        List<byte[]> messages = [[1], [2], [3]]; // count = 3
        var signature = bbs.Sign(keyPair.PrivateKey, messages);

        var act = () => bbs.DeriveProof(keyPair.PublicKey, signature, messages, [badIndex], default);
        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("revealedIndices");
    }

    private static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(s);
    }

    private static string Base64UrlEncode(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
