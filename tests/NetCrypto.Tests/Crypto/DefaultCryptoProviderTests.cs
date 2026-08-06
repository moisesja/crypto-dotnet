using System.Numerics;
using FluentAssertions;
using NetCrypto;

namespace NetCrypto.Tests.Crypto;

public class DefaultCryptoProviderTests
{
    private static readonly BigInteger Secp256k1Order = new(
        Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
        isUnsigned: true,
        isBigEndian: true);

    private readonly DefaultCryptoProvider _crypto = new();
    private readonly DefaultKeyGenerator _keyGen = new();

    [Fact]
    public void SignVerify_Ed25519_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var data = "Hello, World!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Ed25519, keyPair.PublicKey, data, signature);

        signature.Should().HaveCount(64);
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_Ed25519_WrongData_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var data = "Hello"u8.ToArray();
        var wrongData = "Wrong"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Ed25519, keyPair.PublicKey, wrongData, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_Ed25519_WrongKey_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var otherKey = _keyGen.Generate(KeyType.Ed25519);
        var data = "Hello"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Ed25519, otherKey.PublicKey, data, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void SignVerify_P256_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.P256);
        var data = "Hello, P-256!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P256, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P256, keyPair.PublicKey, data, signature);

        valid.Should().BeTrue();
    }

    [Fact]
    public void SignVerify_P384_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.P384);
        var data = "Hello, P-384!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P384, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P384, keyPair.PublicKey, data, signature);

        valid.Should().BeTrue();
    }

    [Fact]
    public void SignVerify_P521_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.P521);
        var data = "Hello, P-521!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P521, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P521, keyPair.PublicKey, data, signature);

        valid.Should().BeTrue();
        keyPair.PublicKey.Length.Should().Be(67); // 1 prefix byte + 66 coordinate bytes
    }

    [Fact]
    public void SignVerify_P521_WrongKey_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.P521);
        var otherKey = _keyGen.Generate(KeyType.P521);
        var data = "Hello, P-521!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P521, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P521, otherKey.PublicKey, data, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void SignVerify_P521_RestoredKey_Works()
    {
        var keyPair = _keyGen.Generate(KeyType.P521);
        var restored = _keyGen.FromPrivateKey(KeyType.P521, keyPair.PrivateKey);
        var data = "Restored P-521 key"u8.ToArray();

        var signature = _crypto.Sign(KeyType.P521, restored.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.P521, restored.PublicKey, data, signature);

        valid.Should().BeTrue();
        restored.PublicKey.Should().Equal(keyPair.PublicKey);
    }

    [Fact]
    public void DeriveSharedSecret_P521_AliceBobAgree()
    {
        var alice = _keyGen.Generate(KeyType.P521);
        var bob = _keyGen.Generate(KeyType.P521);

        var aliceShared = _crypto.DeriveSharedSecret(KeyType.P521, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(KeyType.P521, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(66);
        aliceShared.Should().Equal(bobShared);
    }

    // --- ECDSA signature format: DER vs IEEE P1363 — Issue #62 ---

    [Theory]
    [InlineData(KeyType.P256, 64)]   // 2 × 32 bytes
    [InlineData(KeyType.P384, 96)]   // 2 × 48 bytes
    [InlineData(KeyType.P521, 132)]  // 2 × 66 bytes
    public void Sign_NistEcDsa_IeeeP1363_HasExpectedFixedLength(KeyType keyType, int expectedLength)
    {
        var keyPair = _keyGen.Generate(keyType);
        var data = "JOSE ES256/ES384/ES512 wire format"u8.ToArray();

        var sig = _crypto.Sign(keyType, keyPair.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);

        sig.Should().HaveCount(expectedLength);
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    public void SignVerify_IeeeP1363_RoundTrip(KeyType keyType)
    {
        var keyPair = _keyGen.Generate(keyType);
        var data = "P1363 round trip"u8.ToArray();

        var sig = _crypto.Sign(keyType, keyPair.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);
        var ok = _crypto.Verify(keyType, keyPair.PublicKey, data, sig, EcdsaSignatureFormat.IeeeP1363);

        ok.Should().BeTrue();
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    public void SignVerify_Der_Default_StillWorks(KeyType keyType)
    {
        // The 3-arg legacy Sign/Verify keep DER for back-compat.
        var keyPair = _keyGen.Generate(keyType);
        var data = "DER round trip"u8.ToArray();

        var sig = _crypto.Sign(keyType, keyPair.PrivateKey, data);
        var ok = _crypto.Verify(keyType, keyPair.PublicKey, data, sig);

        ok.Should().BeTrue();
        // DER signature is variable-length and longer than the corresponding P1363 form,
        // because of ASN.1 SEQUENCE / INTEGER tag + length overhead.
        sig.Length.Should().BeGreaterThan(keyType switch
        {
            KeyType.P256 => 64,
            KeyType.P384 => 96,
            KeyType.P521 => 132,
            _ => throw new InvalidOperationException()
        });
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    public void Verify_MismatchedFormat_ReturnsFalseNotThrow(KeyType keyType)
    {
        var keyPair = _keyGen.Generate(keyType);
        var data = "Mismatched format"u8.ToArray();

        // Sign as DER but verify as P1363.
        var derSig = _crypto.Sign(keyType, keyPair.PrivateKey, data, EcdsaSignatureFormat.Der);
        var act1 = () => _crypto.Verify(keyType, keyPair.PublicKey, data, derSig, EcdsaSignatureFormat.IeeeP1363);
        act1.Should().NotThrow();
        _crypto.Verify(keyType, keyPair.PublicKey, data, derSig, EcdsaSignatureFormat.IeeeP1363).Should().BeFalse();

        // Sign as P1363 but verify as DER.
        var p1363Sig = _crypto.Sign(keyType, keyPair.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);
        var act2 = () => _crypto.Verify(keyType, keyPair.PublicKey, data, p1363Sig, EcdsaSignatureFormat.Der);
        act2.Should().NotThrow();
        _crypto.Verify(keyType, keyPair.PublicKey, data, p1363Sig, EcdsaSignatureFormat.Der).Should().BeFalse();
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    public void Verify_MalformedP1363Signature_ReturnsFalseNotThrow(KeyType keyType)
    {
        // Backend-independent contract: a malformed P1363 signature — wrong length, or
        // correct length but garbage — verifies as false and never throws, regardless of
        // whether the platform backend (Windows CNG vs OpenSSL) throws or returns false.
        var keyPair = _keyGen.Generate(keyType);
        var data = "malformed p1363"u8.ToArray();
        var valid = _crypto.Sign(keyType, keyPair.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);

        var truncated = valid[..^1];
        var garbageSameLength = new byte[valid.Length];

        var verifyTruncated = () => _crypto.Verify(keyType, keyPair.PublicKey, data, truncated, EcdsaSignatureFormat.IeeeP1363);
        verifyTruncated.Should().NotThrow();
        verifyTruncated().Should().BeFalse();

        var verifyGarbage = () => _crypto.Verify(keyType, keyPair.PublicKey, data, garbageSameLength, EcdsaSignatureFormat.IeeeP1363);
        verifyGarbage.Should().NotThrow();
        verifyGarbage().Should().BeFalse();
    }

    [Fact]
    public void Verify_CrossCurveKey_ReturnsFalseNotThrow()
    {
        // A P-256 signature verified against a P-384 key must be a clean false, not an
        // exception — the field sizes don't even match.
        var data = "cross curve"u8.ToArray();
        var p256 = _keyGen.Generate(KeyType.P256);
        var p384 = _keyGen.Generate(KeyType.P384);
        var p256Sig = _crypto.Sign(KeyType.P256, p256.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);

        var act = () => _crypto.Verify(KeyType.P384, p384.PublicKey, data, p256Sig, EcdsaSignatureFormat.IeeeP1363);
        act.Should().NotThrow();
        act().Should().BeFalse();
    }

    [Fact]
    public void Sign_Ed25519_IgnoresFormatParameter()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        var data = "EdDSA wire format is fixed"u8.ToArray();

        var derCall = _crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data, EcdsaSignatureFormat.Der);
        var p1363Call = _crypto.Sign(KeyType.Ed25519, keyPair.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);

        // Both produce a 64-byte EdDSA signature; the format param has no effect.
        derCall.Should().HaveCount(64);
        p1363Call.Should().HaveCount(64);
        _crypto.Verify(KeyType.Ed25519, keyPair.PublicKey, data, derCall, EcdsaSignatureFormat.IeeeP1363).Should().BeTrue();
    }

    [Fact]
    public void Sign_Secp256k1_IsAlreadyP1363Format()
    {
        // NBitcoin returns 64-byte compact (R‖S) which is structurally identical to P1363.
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var data = "secp256k1 compact"u8.ToArray();

        var sig = _crypto.Sign(KeyType.Secp256k1, keyPair.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);

        sig.Should().HaveCount(64);
        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, sig).Should().BeTrue();
    }

    [Fact]
    public void SignVerify_Secp256k1_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var data = "Hello, secp256k1!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Secp256k1, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, signature);

        signature.Should().HaveCount(64); // compact format
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_Secp256k1_HighSEquivalent_AcceptsRfc8812Signature()
    {
        var privateKey = new byte[32];
        privateKey[^1] = 1;
        var keyPair = _keyGen.FromPrivateKey(KeyType.Secp256k1, privateKey);
        var data = "RFC 8812 ES256K high-S interoperability"u8.ToArray();
        var lowSignature = _crypto.Sign(KeyType.Secp256k1, keyPair.PrivateKey, data);

        var lowS = ReadScalar(lowSignature.AsSpan(32));
        var highS = Secp256k1Order - lowS;
        var highSignature = (byte[])lowSignature.Clone();
        WriteScalar(highS, highSignature.AsSpan(32));
        var uncompressedPublicKey = KeyType.Secp256k1.ToUncompressed(keyPair.PublicKey);

        lowS.Should().BeGreaterThan(BigInteger.Zero);
        lowS.Should().BeLessThanOrEqualTo(Secp256k1Order / 2);
        highS.Should().BeGreaterThan(Secp256k1Order / 2);
        highS.Should().BeLessThan(Secp256k1Order);
        (lowS + highS).Should().Be(Secp256k1Order);
        highSignature.AsSpan(0, 32).SequenceEqual(lowSignature.AsSpan(0, 32)).Should().BeTrue(
            "malleating S must leave R byte-identical");

        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, lowSignature).Should().BeTrue();
        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, highSignature).Should().BeTrue();
        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, highSignature, EcdsaSignatureFormat.Der)
            .Should().BeTrue("the format argument is ignored for compact secp256k1 signatures");
        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, highSignature, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue("the format argument is ignored for compact secp256k1 signatures");
        _crypto.Verify(KeyType.Secp256k1, uncompressedPublicKey, data, highSignature)
            .Should().BeTrue("high-S verification must work with either accepted SEC1 public-key encoding");
    }

    [Fact]
    public void Verify_Secp256k1_HighSEquivalent_RemainsBoundToKeyAndData()
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var otherKeyPair = _keyGen.Generate(KeyType.Secp256k1);
        var data = "high-S signatures remain ordinary ECDSA signatures"u8.ToArray();
        var lowSignature = _crypto.Sign(KeyType.Secp256k1, keyPair.PrivateKey, data);
        var highSignature = ToHighS(lowSignature);
        var tamperedR = (byte[])highSignature.Clone();
        tamperedR[0] ^= 0x01;

        // S is the only scalar with a second valid representation. Negating R is the structurally
        // identical transformation applied to the other half, and it must stay rejected — this is
        // the property that proves normalization widened the accept set by exactly one encoding.
        var negatedR = (byte[])lowSignature.Clone();
        WriteScalar(Secp256k1Order - ReadScalar(lowSignature.AsSpan(0, 32)), negatedR.AsSpan(0, 32));
        var negatedBoth = ToHighS(negatedR);

        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, "different data"u8, highSignature)
            .Should().BeFalse();
        _crypto.Verify(KeyType.Secp256k1, otherKeyPair.PublicKey, data, highSignature)
            .Should().BeFalse();
        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, tamperedR)
            .Should().BeFalse();
        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, negatedR)
            .Should().BeFalse("(n-R, S) is not a valid signature — only S has a second representation");
        _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, negatedBoth)
            .Should().BeFalse("(n-R, n-S) is not a valid signature either");
    }

    // Two distinct rejection reasons are asserted together because both must surface the same way
    // — false, never an exception. Zero/out-of-range scalars are structurally invalid; the
    // half-order and n-1 cases are perfectly valid scalars that simply are not a signature for
    // this key, and they pin that normalization does not change the boundary at S == n/2.
    [Fact]
    public void Verify_Secp256k1_NonVerifyingCompactScalars_ReturnFalseWithoutThrowing()
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var data = "invalid compact scalar boundaries"u8.ToArray();
        var one = new BigInteger(1);
        var halfOrder = Secp256k1Order / 2;
        var invalidSignatures = new[]
        {
            CompactSignature(BigInteger.Zero, one),
            CompactSignature(one, BigInteger.Zero),
            CompactSignature(Secp256k1Order, one),
            CompactSignature(one, Secp256k1Order),
            CompactSignature(one, Secp256k1Order + one),
            CompactSignature(one, Secp256k1Order - one),
            CompactSignature(one, halfOrder),
            CompactSignature(one, halfOrder + one),
            Enumerable.Repeat((byte)0xff, 64).ToArray()
        };

        foreach (var signature in invalidSignatures)
        {
            var verify = () => _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, signature);
            verify.Should().NotThrow();
            verify().Should().BeFalse();
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(65)]
    [InlineData(128)]
    public void Verify_Secp256k1_InvalidCompactLength_ReturnsFalseWithoutThrowing(int length)
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var verify = () => _crypto.Verify(
            KeyType.Secp256k1, keyPair.PublicKey, "invalid compact length"u8, new byte[length]);

        verify.Should().NotThrow();
        verify().Should().BeFalse();
    }

    [Fact]
    public void Sign_Secp256k1_RemainsLowS()
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);

        for (var i = 0; i < 32; i++)
        {
            var signature = _crypto.Sign(KeyType.Secp256k1, keyPair.PrivateKey, BitConverter.GetBytes(i));
            var s = ReadScalar(signature.AsSpan(32));

            s.Should().BeGreaterThan(BigInteger.Zero);
            s.Should().BeLessThanOrEqualTo(Secp256k1Order / 2,
                "secp256k1 signing must retain its canonical low-S output policy (iteration {0})", i);
            _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, BitConverter.GetBytes(i), ToHighS(signature))
                .Should().BeTrue("every valid signature must verify through its high-S twin (iteration {0})", i);
        }
    }

    [Fact]
    public void Verify_Secp256k1_DeterministicCompactJunkNeverThrowsOrVerifies()
    {
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var data = "normalization must not turn junk into a signature"u8.ToArray();
        var random = new Random(23);

        for (var i = 0; i < 256; i++)
        {
            var signature = new byte[64];
            random.NextBytes(signature);
            var verify = () => _crypto.Verify(KeyType.Secp256k1, keyPair.PublicKey, data, signature);

            verify.Should().NotThrow();
            verify().Should().BeFalse("deterministic junk sample {0} was not signed by the key", i);
        }
    }

    // Documents why the "signature bytes are not a unique identifier" warning is written against
    // ECDSA generally rather than secp256k1 alone: the NIST curves have always accepted the
    // (R, n-S) twin, because neither FIPS 186-5 nor .NET's ECDsa imposes a low-S rule. Issue #23
    // aligned secp256k1 with this behavior; it did not invent it.
    [Theory]
    [InlineData(KeyType.P256, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")]
    [InlineData(KeyType.P384, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973")]
    [InlineData(KeyType.P521, "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409")]
    public void Verify_NistEcdsa_AlreadyAcceptsNegatedS(KeyType keyType, string groupOrderHex)
    {
        var order = new BigInteger(Convert.FromHexString(groupOrderHex), isUnsigned: true, isBigEndian: true);
        var keyPair = _keyGen.Generate(keyType);
        var data = "ECDSA S-malleability is not specific to secp256k1"u8.ToArray();

        var signature = _crypto.Sign(keyType, keyPair.PrivateKey, data, EcdsaSignatureFormat.IeeeP1363);
        var scalarSize = signature.Length / 2;
        var malleated = (byte[])signature.Clone();
        WriteScalar(order - ReadScalar(signature.AsSpan(scalarSize)), malleated.AsSpan(scalarSize));

        malleated.AsSpan(0, scalarSize).SequenceEqual(signature.AsSpan(0, scalarSize)).Should().BeTrue(
            "negating S must leave R byte-identical");
        malleated.Should().NotEqual(signature, "the malleated signature must be a different encoding");

        _crypto.Verify(keyType, keyPair.PublicKey, data, signature, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue();
        _crypto.Verify(keyType, keyPair.PublicKey, data, malleated, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue("{0} accepts the (R, n-S) twin independently of the issue #23 change", keyType);
    }

    private static byte[] ToHighS(byte[] lowSignature)
    {
        var highSignature = (byte[])lowSignature.Clone();
        WriteScalar(Secp256k1Order - ReadScalar(lowSignature.AsSpan(32)), highSignature.AsSpan(32));
        return highSignature;
    }

    private static byte[] CompactSignature(BigInteger r, BigInteger s)
    {
        var signature = new byte[64];
        WriteScalar(r, signature.AsSpan(0, 32));
        WriteScalar(s, signature.AsSpan(32, 32));
        return signature;
    }

    private static BigInteger ReadScalar(ReadOnlySpan<byte> scalar)
        => new(scalar, isUnsigned: true, isBigEndian: true);

    private static void WriteScalar(BigInteger scalar, Span<byte> destination)
    {
        destination.Clear();
        scalar.TryWriteBytes(destination, out var bytesWritten, isUnsigned: true, isBigEndian: true)
            .Should().BeTrue();
        if (bytesWritten < destination.Length)
            destination[..bytesWritten].CopyTo(destination[(destination.Length - bytesWritten)..]);
        destination[..(destination.Length - bytesWritten)].Clear();
    }

    [Fact]
    public void Sign_X25519_ThrowsArgumentException()
    {
        var keyPair = _keyGen.Generate(KeyType.X25519);
        var data = "Hello"u8.ToArray();

        var act = () => _crypto.Sign(KeyType.X25519, keyPair.PrivateKey, data);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void KeyAgreement_X25519_ProducesSharedSecret()
    {
        var aliceKey = _keyGen.Generate(KeyType.X25519);
        var bobKey = _keyGen.Generate(KeyType.X25519);

        var aliceShared = _crypto.KeyAgreement(aliceKey.PrivateKey, bobKey.PublicKey);
        var bobShared = _crypto.KeyAgreement(bobKey.PrivateKey, aliceKey.PublicKey);

        aliceShared.Should().NotBeEmpty();
        bobShared.Should().NotBeEmpty();
        aliceShared.Should().Equal(bobShared);
    }

    // --- DeriveSharedSecret (raw ECDH "Z") — Issue #60 ---

    [Fact]
    public void DeriveSharedSecret_X25519_MatchesRfc7748TestVector()
    {
        // RFC 7748 §6.1 — X25519 Diffie-Hellman test vector.
        var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var bobPublic = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        var expectedShared = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        var shared = _crypto.DeriveSharedSecret(KeyType.X25519, alicePrivate, bobPublic);

        shared.Should().Equal(expectedShared);
    }

    [Fact]
    public void DeriveSharedSecret_X25519_AliceBobAgree()
    {
        var alice = _keyGen.Generate(KeyType.X25519);
        var bob = _keyGen.Generate(KeyType.X25519);

        var aliceShared = _crypto.DeriveSharedSecret(KeyType.X25519, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(KeyType.X25519, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(32);
        aliceShared.Should().Equal(bobShared);
    }

    [Fact]
    public void DeriveSharedSecret_P256_AliceBobAgree()
    {
        var alice = _keyGen.Generate(KeyType.P256);
        var bob = _keyGen.Generate(KeyType.P256);

        var aliceShared = _crypto.DeriveSharedSecret(KeyType.P256, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(KeyType.P256, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(32);
        aliceShared.Should().Equal(bobShared);
    }

    [Fact]
    public void DeriveSharedSecret_P256_MatchesRfc5903KAT()
    {
        // RFC 5903 §8.1 — ECP-256 ECDH known-answer test.
        // Initiator private "i" and responder public point (gr_x, gr_y); expected raw Z.
        var iPrivate = Convert.FromHexString("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
        var grX = Convert.FromHexString("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63");
        var grY = Convert.FromHexString("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB");
        var expectedZ = Convert.FromHexString("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

        // Build SEC1 uncompressed public key 0x04 || X || Y.
        var grPublic = new byte[1 + grX.Length + grY.Length];
        grPublic[0] = 0x04;
        Buffer.BlockCopy(grX, 0, grPublic, 1, grX.Length);
        Buffer.BlockCopy(grY, 0, grPublic, 1 + grX.Length, grY.Length);

        var z = _crypto.DeriveSharedSecret(KeyType.P256, iPrivate, grPublic);

        z.Should().Equal(expectedZ);
    }

    [Fact]
    public void DeriveSharedSecret_P384_MatchesRfc5903KAT()
    {
        // RFC 5903 §8.2 — ECP-384 ECDH known-answer test.
        var iPrivate = Convert.FromHexString(
            "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194");
        var grX = Convert.FromHexString(
            "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571");
        var grY = Convert.FromHexString(
            "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C");
        var expectedZ = Convert.FromHexString(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746");

        var grPublic = new byte[1 + grX.Length + grY.Length];
        grPublic[0] = 0x04;
        Buffer.BlockCopy(grX, 0, grPublic, 1, grX.Length);
        Buffer.BlockCopy(grY, 0, grPublic, 1 + grX.Length, grY.Length);

        var z = _crypto.DeriveSharedSecret(KeyType.P384, iPrivate, grPublic);

        z.Should().Equal(expectedZ);
    }

    [Fact]
    public void DeriveSharedSecret_P384_AliceBobAgree()
    {
        var alice = _keyGen.Generate(KeyType.P384);
        var bob = _keyGen.Generate(KeyType.P384);

        var aliceShared = _crypto.DeriveSharedSecret(KeyType.P384, alice.PrivateKey, bob.PublicKey);
        var bobShared = _crypto.DeriveSharedSecret(KeyType.P384, bob.PrivateKey, alice.PublicKey);

        aliceShared.Should().HaveCount(48);
        aliceShared.Should().Equal(bobShared);
    }

    [Fact]
    public void DeriveSharedSecret_P256_AcceptsUncompressedPublicKey()
    {
        var alice = _keyGen.Generate(KeyType.P256);
        var bob = _keyGen.Generate(KeyType.P256);

        // Decompress Bob's public key to uncompressed SEC1 form (0x04 || X || Y).
        using var ecdsa = System.Security.Cryptography.ECDsa.Create();
        ecdsa.ImportParameters(DefaultCryptoProvider.DecompressEcPoint(bob.PublicKey, System.Security.Cryptography.ECCurve.NamedCurves.nistP256));
        var p = ecdsa.ExportParameters(false);
        var uncompressed = new byte[1 + p.Q.X!.Length + p.Q.Y!.Length];
        uncompressed[0] = 0x04;
        p.Q.X.CopyTo(uncompressed, 1);
        p.Q.Y.CopyTo(uncompressed, 1 + p.Q.X.Length);

        var fromCompressed = _crypto.DeriveSharedSecret(KeyType.P256, alice.PrivateKey, bob.PublicKey);
        var fromUncompressed = _crypto.DeriveSharedSecret(KeyType.P256, alice.PrivateKey, uncompressed);

        fromCompressed.Should().Equal(fromUncompressed);
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.Secp256k1)]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void DeriveSharedSecret_NonEcdhKeyType_Throws(KeyType keyType)
    {
        var dummy = new byte[32];
        var act = () => _crypto.DeriveSharedSecret(keyType, dummy, dummy);
        act.Should().Throw<ArgumentException>();
    }

    // --- BLS12-381 G1 (pubkey in G1, signature in G2) ---

    [Fact]
    public void SignVerify_Bls12381G1_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G1);
        var data = "Hello, BLS G1!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G1, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G1, keyPair.PublicKey, data, signature);

        signature.Should().HaveCount(96); // G2 signature compressed
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_Bls12381G1_WrongData_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G1);
        var data = "Hello"u8.ToArray();
        var wrongData = "Wrong"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G1, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G1, keyPair.PublicKey, wrongData, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_Bls12381G1_WrongKey_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G1);
        var otherKey = _keyGen.Generate(KeyType.Bls12381G1);
        var data = "Hello"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G1, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G1, otherKey.PublicKey, data, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void SignVerify_Bls12381G1_RestoredKey_Works()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G1);
        var restored = _keyGen.FromPrivateKey(KeyType.Bls12381G1, keyPair.PrivateKey);
        var data = "Restored key test"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G1, restored.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G1, restored.PublicKey, data, signature);

        valid.Should().BeTrue();
    }

    // --- BLS12-381 G2 (pubkey in G2, signature in G1) ---

    [Fact]
    public void SignVerify_Bls12381G2_RoundTrip()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G2);
        var data = "Hello, BLS G2!"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G2, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G2, keyPair.PublicKey, data, signature);

        signature.Should().HaveCount(48); // G1 signature compressed
        valid.Should().BeTrue();
    }

    [Fact]
    public void Verify_Bls12381G2_WrongData_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G2);
        var data = "Hello"u8.ToArray();
        var wrongData = "Wrong"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G2, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G2, keyPair.PublicKey, wrongData, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void Verify_Bls12381G2_WrongKey_ReturnsFalse()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G2);
        var otherKey = _keyGen.Generate(KeyType.Bls12381G2);
        var data = "Hello"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G2, keyPair.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G2, otherKey.PublicKey, data, signature);

        valid.Should().BeFalse();
    }

    [Fact]
    public void SignVerify_Bls12381G2_RestoredKey_Works()
    {
        var keyPair = _keyGen.Generate(KeyType.Bls12381G2);
        var restored = _keyGen.FromPrivateKey(KeyType.Bls12381G2, keyPair.PrivateKey);
        var data = "Restored key test"u8.ToArray();

        var signature = _crypto.Sign(KeyType.Bls12381G2, restored.PrivateKey, data);
        var valid = _crypto.Verify(KeyType.Bls12381G2, restored.PublicKey, data, signature);

        valid.Should().BeTrue();
    }
}
