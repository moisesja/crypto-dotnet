using System.Security.Cryptography;
using FluentAssertions;
using NetCrypto;
using NetCrypto.Native;

namespace NetCrypto.Tests.Crypto;

[Trait("Category", "NativeFFI")]
public class DefaultBbsCryptoProviderTests
{
    private readonly DefaultBbsCryptoProvider _bbs = new();

    /// <summary>
    /// Generate a BBS+ keypair via the native FFI layer.
    /// Returns (secretKey: 32 bytes, publicKey: 96 bytes).
    /// </summary>
    private static (byte[] sk, byte[] pk) GenerateBbsKeyPair()
    {
        var ikm = new byte[32];
        RandomNumberGenerator.Fill(ikm);

        var sk = new byte[32];
        var pk = new byte[96];
        var rc = ZkryptiumNative.bbs_keygen(ikm, (nuint)ikm.Length, ReadOnlySpan<byte>.Empty, 0, sk, pk);
        if (rc != 0)
            throw new CryptographicException("BBS+ key generation failed in test setup.");
        return (sk, pk);
    }

    // --- Sign / Verify ---

    [Fact]
    public void SignVerify_SingleMessage_RoundTrip()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]> { "Hello, BBS+"u8.ToArray() };

        var signature = _bbs.Sign(sk, messages);
        var valid = _bbs.Verify(pk, signature, messages);

        signature.Should().HaveCount(80);
        valid.Should().BeTrue();
    }

    [Fact]
    public void SignVerify_MultipleMessages_RoundTrip()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "name: Alice"u8.ToArray(),
            "age: 30"u8.ToArray(),
            "email: alice@example.com"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        var valid = _bbs.Verify(pk, signature, messages);

        signature.Should().HaveCount(80);
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_WrongMessage_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]> { "correct"u8.ToArray() };
        var wrongMessages = new List<byte[]> { "wrong"u8.ToArray() };

        var signature = _bbs.Sign(sk, messages);
        var valid = _bbs.Verify(pk, signature, wrongMessages);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        var (sk1, _) = GenerateBbsKeyPair();
        var (_, pk2) = GenerateBbsKeyPair();
        var messages = new List<byte[]> { "test"u8.ToArray() };

        var signature = _bbs.Sign(sk1, messages);
        var valid = _bbs.Verify(pk2, signature, messages);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]> { "test"u8.ToArray() };

        var signature = _bbs.Sign(sk, messages);
        signature[0] ^= 0xFF; // flip bits
        var valid = _bbs.Verify(pk, signature, messages);

        valid.Should().BeFalse();
    }

    // --- Selective Disclosure Proofs ---

    [Fact]
    public void DeriveProof_VerifyProof_RoundTrip()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "name: Alice"u8.ToArray(),
            "age: 30"u8.ToArray(),
            "email: alice@example.com"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);

        // Disclose only message 0 (name) and 2 (email)
        var revealedIndices = new List<int> { 0, 2 };
        var nonce = "verifier-challenge"u8.ToArray();

        var proof = _bbs.DeriveProof(pk, signature, messages, revealedIndices, nonce);
        proof.Should().NotBeEmpty();

        // Verify with only the disclosed messages
        var revealedMessages = new List<byte[]>
        {
            messages[0],
            messages[2]
        };
        var valid = _bbs.VerifyProof(pk, proof, revealedMessages, revealedIndices, nonce);
        valid.Should().BeTrue();
    }

    [Fact]
    public void VerifyProof_WrongNonce_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "msg1"u8.ToArray(),
            "msg2"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        var revealedIndices = new List<int> { 0 };
        var nonce = "nonce1"u8.ToArray();

        var proof = _bbs.DeriveProof(pk, signature, messages, revealedIndices, nonce);

        var wrongNonce = "nonce2"u8.ToArray();
        var revealedMessages = new List<byte[]> { messages[0] };
        var valid = _bbs.VerifyProof(pk, proof, revealedMessages, revealedIndices, wrongNonce);
        valid.Should().BeFalse();
    }

    [Fact]
    public void VerifyProof_WrongDisclosedMessage_ReturnsFalse()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "real-name"u8.ToArray(),
            "real-age"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        var revealedIndices = new List<int> { 0 };
        var nonce = "nonce"u8.ToArray();

        var proof = _bbs.DeriveProof(pk, signature, messages, revealedIndices, nonce);

        // Try to verify with a different message at the disclosed index
        var fakeMessages = new List<byte[]> { "fake-name"u8.ToArray() };
        var valid = _bbs.VerifyProof(pk, proof, fakeMessages, revealedIndices, nonce);
        valid.Should().BeFalse();
    }

    [Fact]
    public void DeriveProof_DiscloseAllMessages_VerifiesSuccessfully()
    {
        var (sk, pk) = GenerateBbsKeyPair();
        var messages = new List<byte[]>
        {
            "a"u8.ToArray(),
            "b"u8.ToArray(),
            "c"u8.ToArray()
        };

        var signature = _bbs.Sign(sk, messages);
        var allIndices = new List<int> { 0, 1, 2 };
        var nonce = "nonce"u8.ToArray();

        var proof = _bbs.DeriveProof(pk, signature, messages, allIndices, nonce);
        var valid = _bbs.VerifyProof(pk, proof, messages, allIndices, nonce);
        valid.Should().BeTrue();
    }

    // --- Key interop: Nethermind (blst) key generation → zkryptium BBS+ ---

    [Fact]
    public void Sign_WithNethermindGeneratedKey_VerifiesWithPublishedPublicKey()
    {
        // Generate key pair the production way (Nethermind/blst)
        var keyGen = new DefaultKeyGenerator();
        var keyPair = keyGen.Generate(KeyType.Bls12381G2);

        // Sign with BBS+ (internally re-derives PK via zkryptium)
        var messages = new List<byte[]> { "interop-test"u8.ToArray() };
        var signature = _bbs.Sign(keyPair.PrivateKey, messages);

        // Verify using the Nethermind-derived public key (the one published in DID documents).
        // This proves both libraries derive the same G2 public key from the same scalar.
        var valid = _bbs.Verify(keyPair.PublicKey, signature, messages);
        valid.Should().BeTrue("Nethermind-derived G2 public key must match zkryptium-derived G2 public key");
    }

    [Fact]
    public void DeriveProof_WithNethermindGeneratedKey_VerifiesWithPublishedPublicKey()
    {
        var keyGen = new DefaultKeyGenerator();
        var keyPair = keyGen.Generate(KeyType.Bls12381G2);

        var messages = new List<byte[]>
        {
            "claim-a"u8.ToArray(),
            "claim-b"u8.ToArray()
        };
        var signature = _bbs.Sign(keyPair.PrivateKey, messages);

        var revealedIndices = new List<int> { 0 };
        var nonce = "verifier-nonce"u8.ToArray();
        var proof = _bbs.DeriveProof(keyPair.PublicKey, signature, messages, revealedIndices, nonce);

        var revealedMessages = new List<byte[]> { messages[0] };
        var valid = _bbs.VerifyProof(keyPair.PublicKey, proof, revealedMessages, revealedIndices, nonce);
        valid.Should().BeTrue("BBS+ proof must verify with Nethermind-derived G2 public key");
    }

    // --- Edge cases ---

    [Fact]
    public void Sign_EmptyMessages_ThrowsArgumentException()
    {
        var (sk, _) = GenerateBbsKeyPair();
        var act = () => _bbs.Sign(sk, new List<byte[]>());
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Sign_WrongKeySize_ThrowsArgumentException()
    {
        var act = () => _bbs.Sign(new byte[16], new List<byte[]> { "x"u8.ToArray() });
        act.Should().Throw<ArgumentException>();
    }
}
