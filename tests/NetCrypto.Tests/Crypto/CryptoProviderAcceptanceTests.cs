using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// FR-3 acceptance tests (netcrypto-prd.md §FR-3 — DefaultCryptoProvider):
/// - Cross-format: a P-256 signature produced as DER verifies as DER and returns false
///   (no throw) when verified as IeeeP1363, and vice versa.
/// - Two-party agreement per ECDH-capable type (X25519, P-256, P-384, P-521): independently
///   generated pairs derive byte-identical shared secrets from both sides; a non-ECDH key
///   type (Ed25519) throws ArgumentException.
/// - Ed25519 sign/verify validated against RFC 8032 §7.1 test vectors (TEST 1–3).
/// </summary>
public class CryptoProviderAcceptanceTests
{
    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DefaultKeyGenerator _keyGen = new();

    // -------- FR-3 AC: cross-format DER vs IEEE P1363 (P-256) --------

    [Fact]
    public void Verify_P256_DerSignature_VerifiesAsDer_FailsCleanlyAsIeeeP1363()
    {
        var keyPair = _keyGen.Generate(KeyType.P256);
        var data = "FR-3 cross-format: DER signature"u8.ToArray();

        var derSig = _crypto.Sign(KeyType.P256, keyPair.PrivateKey, data, EcdsaSignatureFormat.Der);

        // Same format: verifies.
        _crypto.Verify(KeyType.P256, keyPair.PublicKey, data, derSig, EcdsaSignatureFormat.Der)
            .Should().BeTrue();

        // Mismatched format: returns false, never throws.
        var verifyAsP1363 = () => _crypto.Verify(
            KeyType.P256, keyPair.PublicKey, data, derSig, EcdsaSignatureFormat.IeeeP1363);
        verifyAsP1363.Should().NotThrow();
        verifyAsP1363().Should().BeFalse();
    }

    [Fact]
    public void Verify_P256_IeeeP1363Signature_VerifiesAsIeeeP1363_FailsCleanlyAsDer()
    {
        var keyPair = _keyGen.Generate(KeyType.P256);
        var data = "FR-3 cross-format: P1363 signature"u8.ToArray();

        var p1363Sig = _crypto.Sign(KeyType.P256, keyPair.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);

        // Same format: verifies.
        _crypto.Verify(KeyType.P256, keyPair.PublicKey, data, p1363Sig, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue();

        // Mismatched format: returns false, never throws.
        var verifyAsDer = () => _crypto.Verify(
            KeyType.P256, keyPair.PublicKey, data, p1363Sig, EcdsaSignatureFormat.Der);
        verifyAsDer.Should().NotThrow();
        verifyAsDer().Should().BeFalse();
    }

    // -------- FR-3 AC: two-party agreement per ECDH-capable type --------

    [Theory]
    [InlineData(KeyType.X25519, 32)] // raw X25519 Z is 32 bytes
    [InlineData(KeyType.P256, 32)]   // raw ECDH Z = field element, 32 bytes
    [InlineData(KeyType.P384, 48)]   // 48 bytes
    [InlineData(KeyType.P521, 66)]   // 66 bytes
    public void DeriveSharedSecret_EcdhCapableType_BothSidesDeriveIdenticalSecret(
        KeyType keyType, int expectedLength)
    {
        var alice = _keyGen.Generate(keyType);
        var bob = _keyGen.Generate(keyType);

        var aliceShared = _crypto.DeriveSharedSecret(keyType, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(keyType, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(expectedLength);
        aliceShared.Should().Equal(bobShared);
    }

    [Fact]
    public void DeriveSharedSecret_Ed25519_ThrowsArgumentException()
    {
        // Ed25519 is a signature key type, not ECDH-capable.
        var alice = _keyGen.Generate(KeyType.Ed25519);
        var bob = _keyGen.Generate(KeyType.Ed25519);

        var act = () => _crypto.DeriveSharedSecret(KeyType.Ed25519, alice.PrivateKey, bob.PublicKey);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void KeyAgreement_X25519_HkdfWrapper_BothSidesDeriveIdenticalSecret()
    {
        // KeyAgreement is the HKDF-SHA256 wrapper over the raw X25519 shared secret;
        // both directions must still agree byte-for-byte.
        var alice = _keyGen.Generate(KeyType.X25519);
        var bob = _keyGen.Generate(KeyType.X25519);

        var aliceShared = _crypto.KeyAgreement(alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.KeyAgreement(bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().NotBeEmpty();
        aliceShared.Should().Equal(bobShared);
    }

    // -------- FR-3 AC: RFC 8032 §7.1 Ed25519 test vectors (TEST 1–3) --------
    //
    // Vectors extracted from https://www.rfc-editor.org/rfc/rfc8032.txt, Section 7.1
    // ("Test Vectors for Ed25519"). The RFC's "SECRET KEY" is the 32-byte seed, which is
    // exactly the private-key representation DefaultCryptoProvider uses for Ed25519.

    // RFC 8032 §7.1 TEST 1 (empty message)
    private const string Test1SecretKeyHex =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    private const string Test1PublicKeyHex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    private const string Test1MessageHex = "";
    private const string Test1SignatureHex =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    // RFC 8032 §7.1 TEST 2 (1-byte message 0x72)
    private const string Test2SecretKeyHex =
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    private const string Test2PublicKeyHex =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    private const string Test2MessageHex = "72";
    private const string Test2SignatureHex =
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    // RFC 8032 §7.1 TEST 3 (2-byte message 0xaf82)
    private const string Test3SecretKeyHex =
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    private const string Test3PublicKeyHex =
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    private const string Test3MessageHex = "af82";
    private const string Test3SignatureHex =
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

    [Theory]
    // RFC 8032 §7.1 TEST 1
    [InlineData(Test1SecretKeyHex, Test1PublicKeyHex, Test1MessageHex, Test1SignatureHex)]
    // RFC 8032 §7.1 TEST 2
    [InlineData(Test2SecretKeyHex, Test2PublicKeyHex, Test2MessageHex, Test2SignatureHex)]
    // RFC 8032 §7.1 TEST 3
    [InlineData(Test3SecretKeyHex, Test3PublicKeyHex, Test3MessageHex, Test3SignatureHex)]
    public void SignVerify_Ed25519_Rfc8032Vector_MatchesExpectedSignatureAndVerifies(
        string secretKeyHex, string publicKeyHex, string messageHex, string signatureHex)
    {
        var seed = Convert.FromHexString(secretKeyHex);
        var publicKey = Convert.FromHexString(publicKeyHex);
        var message = Convert.FromHexString(messageHex);
        var expectedSignature = Convert.FromHexString(signatureHex);

        // Ed25519 is deterministic (RFC 8032 §5.1.6): signing the vector's message with the
        // vector's seed must reproduce the vector's signature exactly.
        var signature = _crypto.Sign(KeyType.Ed25519, seed, message);
        signature.Should().Equal(expectedSignature);

        // And the vector's signature must verify under the vector's public key.
        var valid = _crypto.Verify(KeyType.Ed25519, publicKey, message, expectedSignature);
        valid.Should().BeTrue();
    }
}
