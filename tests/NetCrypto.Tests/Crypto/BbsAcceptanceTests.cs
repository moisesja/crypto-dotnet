using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;
using NetCrypto.Native;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// Acceptance tests for PRD FR-5 (BBS provider with ciphersuite parameter), netcrypto-prd.md §FR-5:
/// (a) full round-trip — keygen → sign(3 messages) → verify(true) → DeriveProof(reveal {0,2}) →
///     VerifyProof(true); tampering a revealed message makes VerifyProof return false;
/// (b) size invariants — SK 32, PK 96, signature 80 bytes;
/// (c) deterministic keygen fixture from draft-irtf-cfrg-bbs-signatures-10 (BLS12-381-SHA-256)
///     proving the wrapped zkryptium build matches draft-10;
/// (d) ciphersuite parameter — unsupported suite throws <see cref="NotSupportedException"/>
///     naming the suite; the default constructor selects
///     <see cref="BbsCiphersuite.Bls12381Sha256"/>.
/// </summary>
[Trait("Category", "NativeFFI")]
public class BbsAcceptanceTests
{
    private readonly DefaultBbsCryptoProvider _bbs = new();

    /// <summary>
    /// Generate a BBS keypair via the native FFI layer with random IKM and the spec-default
    /// (empty) key_info. Returns (secretKey: 32 bytes, publicKey: 96 bytes).
    /// </summary>
    private static (byte[] sk, byte[] pk) GenerateBbsKeyPair()
    {
        var ikm = new byte[32];
        RandomNumberGenerator.Fill(ikm);

        var sk = new byte[32];
        var pk = new byte[96];
        var rc = ZkryptiumNative.bbs_keygen(ikm, (nuint)ikm.Length, ReadOnlySpan<byte>.Empty, 0, sk, pk);
        rc.Should().Be(0, "BBS key generation must succeed when the native library is present");
        return (sk, pk);
    }

    // FR-5 acceptance criterion (netcrypto-prd.md §FR-5): "BBS round-trip test passes on a
    // platform with the native library: keygen → sign(3 messages) → verify(true) →
    // DeriveProof(reveal indices {0,2}) → VerifyProof(true); tamper any revealed message →
    // VerifyProof(false)."
    [Fact]
    public void Bbs_FullRoundTrip_SignVerifyDeriveProofVerifyProof_AndTamperedRevealFails()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "given-name: Alice"u8.ToArray(),
            "birth-date: 1990-01-01"u8.ToArray(),
            "citizenship: Wonderland"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        _bbs.Verify(pk, signature, messages).Should().BeTrue("the full message set was signed with the matching key");

        var revealedIndices = new List<int> { 0, 2 };
        var nonce = "fr5-acceptance-nonce"u8.ToArray();
        var proof = _bbs.DeriveProof(pk, signature, messages, revealedIndices, nonce);
        proof.Should().NotBeEmpty();

        var revealedMessages = new List<byte[]> { messages[0], messages[2] };
        _bbs.VerifyProof(pk, proof, revealedMessages, revealedIndices, nonce)
            .Should().BeTrue("the proof discloses exactly messages {0,2}");

        // Tamper one revealed message — the proof must no longer verify.
        var tamperedMessages = new List<byte[]>
        {
            messages[0],
            "citizenship: Mordor"u8.ToArray()
        };
        _bbs.VerifyProof(pk, proof, tamperedMessages, revealedIndices, nonce)
            .Should().BeFalse("a tampered revealed message must invalidate the proof");
    }

    // FR-5 acceptance criterion (netcrypto-prd.md §FR-5): "Size invariants asserted:
    // SK 32, PK 96, signature 80 bytes."
    [Fact]
    public void Bbs_SizeInvariants_Sk32Pk96Signature80()
    {
        var (sk, pk) = GenerateBbsKeyPair();

        sk.Should().HaveCount(32);
        pk.Should().HaveCount(96);
        // The FFI must actually have written into the fixed-size output buffers.
        sk.Should().Contain(b => b != 0, "keygen must populate the 32-byte secret key");
        pk.Should().Contain(b => b != 0, "keygen must populate the 96-byte public key");

        var signature = _bbs.Sign(sk, new List<byte[]> { "size-invariant"u8.ToArray() });
        signature.Should().HaveCount(80);
    }

    // --- draft-10 KeyGen fixture (BLS12-381-SHA-256) ---

    // Test vector from draft-irtf-cfrg-bbs-signatures-10 §8.4.1 "Key Pair" (BLS12381-SHA-256
    // Test Vectors): https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.txt
    // key_material (ASCII "this-IS-just-an-Test-IKM-to-generate-$e(r@t#-key"):
    private const string Draft10KeyMaterialHex =
        "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";

    // §8.4.1 key_info (ASCII "this-IS-some-key-metadata-to-be-used-in-test-key-gen"):
    private const string Draft10KeyInfoHex =
        "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";

    // §8.4.1 expected SK (KeyGen output, §3.4.1, with the default key_dst
    // api_id || "KEYGEN_DST_" = BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_KEYGEN_DST_):
    private const string Draft10ExpectedSkHex =
        "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc";

    // §8.4.1 expected PK (SkToPk output, §3.4.2, on the SK above):
    private const string Draft10ExpectedPkHex =
        "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f285" +
        "1bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1" +
        "e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c";

    // FR-5 acceptance criterion (netcrypto-prd.md §FR-5): "Keygen fixture test: deterministic
    // IKM from draft-irtf-cfrg-bbs-signatures-10 BLS12-381-SHA-256 test fixtures produces the
    // fixture's expected SK/PK through the FFI (proves the wrapped zkryptium build matches
    // draft-10; cite the fixture used in the test)."
    [Fact]
    public void BbsKeygen_Draft10Sha256KeyPairFixture_ProducesExpectedSkAndPk()
    {
        var keyMaterial = Convert.FromHexString(Draft10KeyMaterialHex);
        var keyInfo = Convert.FromHexString(Draft10KeyInfoHex);

        var sk = new byte[32];
        var pk = new byte[96];
        // key_dst is not passed through the FFI: per draft-10 §3.4.1 it defaults to
        // ciphersuite api_id || "KEYGEN_DST_", which is exactly the key_dst the §8.4.1
        // fixture declares.
        var rc = ZkryptiumNative.bbs_keygen(
            keyMaterial, (nuint)keyMaterial.Length,
            keyInfo, (nuint)keyInfo.Length,
            sk, pk);

        rc.Should().Be(0, "the draft-10 KeyGen fixture inputs are valid");
        sk.Should().Equal(Convert.FromHexString(Draft10ExpectedSkHex),
            "SK must match draft-irtf-cfrg-bbs-signatures-10 §8.4.1");
        pk.Should().Equal(Convert.FromHexString(Draft10ExpectedPkHex),
            "PK must match draft-irtf-cfrg-bbs-signatures-10 §8.4.1");
    }

    // --- Ciphersuite parameter (FR-5 change 4) ---

    // FR-5 acceptance criterion (netcrypto-prd.md §FR-5):
    // "new DefaultBbsCryptoProvider((BbsCiphersuite)1) throws NotSupportedException."
    [Fact]
    public void Ctor_UnsupportedCiphersuite_ThrowsNotSupportedExceptionNamingTheSuite()
    {
        var unsupported = (BbsCiphersuite)1;

        var act = () => new DefaultBbsCryptoProvider(unsupported);

        act.Should().Throw<NotSupportedException>()
            .Which.Message.Should().Contain(unsupported.ToString(),
                "the exception message must name the unsupported suite");
    }

    [Fact]
    public void Ctor_Default_CiphersuiteIsBls12381Sha256()
    {
        new DefaultBbsCryptoProvider().Ciphersuite.Should().Be(BbsCiphersuite.Bls12381Sha256);
    }
}
