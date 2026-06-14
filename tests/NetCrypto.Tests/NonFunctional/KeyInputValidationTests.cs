using FluentAssertions;

namespace NetCrypto.Tests.NonFunctional;

/// <summary>
/// Locks in the malformed-key-input hardening (security review, preview.3): every byte-oriented
/// key/scalar entry point that hands raw bytes to a cryptographic backend (NSec, Nethermind BLS,
/// or the platform EC import) MUST reject a wrong-length input with a <em>parameter-named</em>
/// <see cref="ArgumentException"/> — not a leaked <c>System.FormatException</c>,
/// <c>Nethermind.Crypto.Bls+BlsException</c>, or platform <c>CryptographicException</c>. The
/// <see cref="InputValidationFuzzTests"/> fuzz-lite suite proves the broad contract (only contract
/// exceptions, ever); this suite pins the stronger, specific guarantee the review demanded.
/// </summary>
public class KeyInputValidationTests
{
    private static readonly DefaultCryptoProvider Provider = new();
    private static readonly DefaultKeyGenerator Generator = new();

    // Wrong lengths around each algorithm's expected size (and the fuzz extremes).
    public static TheoryData<int> WrongLengths32 => new() { 0, 1, 16, 31, 33, 64, 10_000 };

    // ── Ed25519 ──

    [Theory]
    [MemberData(nameof(WrongLengths32))]
    public void Sign_Ed25519_WrongLengthPrivateKey_ThrowsArgumentExceptionWithParameterName(int length)
    {
        var act = () => Provider.Sign(KeyType.Ed25519, new byte[length], [1, 2, 3]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    [Theory]
    [MemberData(nameof(WrongLengths32))]
    public void Verify_Ed25519_WrongLengthPublicKey_ThrowsArgumentExceptionWithParameterName(int length)
    {
        var act = () => Provider.Verify(KeyType.Ed25519, new byte[length], [1, 2, 3], new byte[64]);
        act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
    }

    [Theory]
    [MemberData(nameof(WrongLengths32))]
    public void FromPrivateKey_Ed25519_WrongLength_ThrowsArgumentExceptionWithParameterName(int length)
    {
        var act = () => Generator.FromPrivateKey(KeyType.Ed25519, new byte[length]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    // ── X25519 ──

    [Theory]
    [MemberData(nameof(WrongLengths32))]
    public void KeyAgreement_WrongLengthPrivateKey_ThrowsArgumentExceptionWithParameterName(int length)
    {
        var validPublic = Generator.Generate(KeyType.X25519).PublicKey;
        var act = () => Provider.KeyAgreement(new byte[length], validPublic);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    [Theory]
    [MemberData(nameof(WrongLengths32))]
    public void KeyAgreement_WrongLengthPublicKey_ThrowsArgumentExceptionWithParameterName(int length)
    {
        var validPrivate = Generator.Generate(KeyType.X25519).PrivateKey;
        var act = () => Provider.KeyAgreement(validPrivate, new byte[length]);
        act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
    }

    [Theory]
    [MemberData(nameof(WrongLengths32))]
    public void DeriveSharedSecret_X25519_WrongLengthPrivateKey_ThrowsArgumentExceptionWithParameterName(int length)
    {
        var validPublic = Generator.Generate(KeyType.X25519).PublicKey;
        var act = () => Provider.DeriveSharedSecret(KeyType.X25519, new byte[length], validPublic);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    [Theory]
    [MemberData(nameof(WrongLengths32))]
    public void FromPrivateKey_X25519_WrongLength_ThrowsArgumentExceptionWithParameterName(int length)
    {
        var act = () => Generator.FromPrivateKey(KeyType.X25519, new byte[length]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    // ── BLS12-381 ──

    [Theory]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void Sign_Bls_WrongLengthPrivateKey_ThrowsArgumentExceptionWithParameterName(KeyType keyType)
    {
        foreach (var length in new[] { 0, 1, 31, 33, 10_000 })
        {
            var act = () => Provider.Sign(keyType, new byte[length], [1, 2, 3]);
            act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
        }
    }

    [Theory]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void FromPrivateKey_Bls_WrongLength_ThrowsArgumentExceptionWithParameterName(KeyType keyType)
    {
        foreach (var length in new[] { 0, 1, 31, 33, 10_000 })
        {
            var act = () => Generator.FromPrivateKey(keyType, new byte[length]);
            act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
        }
    }

    [Theory]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void Sign_Bls_ZeroScalar_ThrowsArgumentExceptionNotBlsException(KeyType keyType)
    {
        // A correctly-sized but invalid (all-zero) scalar must still be an ArgumentException,
        // not a leaked Nethermind BlsException.
        var act = () => Provider.Sign(keyType, new byte[32], [1, 2, 3]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    // ── NIST EC private keys (P-256 / P-384 / P-521) ──

    [Theory]
    [InlineData(KeyType.P256, 31)]
    [InlineData(KeyType.P256, 33)]
    [InlineData(KeyType.P384, 47)]
    [InlineData(KeyType.P384, 49)]
    [InlineData(KeyType.P521, 65)]
    [InlineData(KeyType.P521, 67)]
    public void Sign_Nist_WrongLengthPrivateKey_ThrowsArgumentExceptionWithParameterName(KeyType keyType, int length)
    {
        var act = () => Provider.Sign(keyType, new byte[length], [1, 2, 3]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    [Theory]
    [InlineData(KeyType.P256, 31)]
    [InlineData(KeyType.P384, 49)]
    [InlineData(KeyType.P521, 65)]
    public void FromPrivateKey_Nist_WrongLength_ThrowsArgumentExceptionWithParameterName(KeyType keyType, int length)
    {
        var act = () => Generator.FromPrivateKey(keyType, new byte[length]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    [Theory]
    [InlineData(KeyType.P256, 31)]
    [InlineData(KeyType.P384, 49)]
    [InlineData(KeyType.P521, 67)]
    public void DeriveSharedSecret_Nist_WrongLengthPrivateKey_ThrowsArgumentExceptionWithParameterName(KeyType keyType, int length)
    {
        // The private key is validated before the public key is examined, so the wrong-length
        // private key throws with paramName "privateKey" regardless of the (valid) public key.
        var validPublic = Generator.Generate(keyType).PublicKey;
        var act = () => Provider.DeriveSharedSecret(keyType, new byte[length], validPublic);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
    }

    // A wrong-length EC PUBLIC (peer) key is a caller bug, not a point-validity failure: it must throw a
    // parameter-named ArgumentException, not the opaque platform CryptographicException that
    // ImportParameters / decompression would otherwise raise (NFR-3; lesson L5). This is the receive-side
    // counterpart to the wrong-length-private-key guard above, and underpins the IKeyStore.DeriveSharedSecretAsync
    // contract. (Off-curve / out-of-range points of the CORRECT length remain a CryptographicException.)
    [Theory]
    [InlineData(KeyType.P256, 0x02, 32)]   // compressed valid length is 1 + 32 = 33
    [InlineData(KeyType.P256, 0x02, 34)]
    [InlineData(KeyType.P256, 0x04, 64)]   // uncompressed valid length is 1 + 64 = 65
    [InlineData(KeyType.P256, 0x04, 66)]
    [InlineData(KeyType.P384, 0x02, 48)]   // compressed valid = 49
    [InlineData(KeyType.P384, 0x04, 96)]   // uncompressed valid = 97
    [InlineData(KeyType.P521, 0x02, 66)]   // compressed valid = 67
    [InlineData(KeyType.P521, 0x04, 132)]  // uncompressed valid = 133
    public void DeriveSharedSecret_Nist_WrongLengthPublicKey_ThrowsArgumentExceptionWithParameterName(
        KeyType keyType, int prefix, int totalLen)
    {
        var validPrivate = Generator.Generate(keyType).PrivateKey;

        // Valid SEC1 prefix so the input reaches the length check rather than the format check.
        var publicKey = new byte[totalLen];
        publicKey[0] = (byte)prefix;

        var act = () => Provider.DeriveSharedSecret(keyType, validPrivate, publicKey);
        act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
    }

    // A correctly-sized but out-of-range NIST scalar (D = 0, or D >= the curve order n — here the
    // all-0xFF maximum) is not a valid private key. It must surface as a parameter-named
    // ArgumentException, not the opaque platform CryptographicException ImportParameters would
    // otherwise raise — matching the BLS/secp256k1 invalid-scalar behaviour.
    [Theory]
    [InlineData(KeyType.P256, 32)]
    [InlineData(KeyType.P384, 48)]
    [InlineData(KeyType.P521, 66)]
    public void Sign_Nist_OutOfRangeScalar_ThrowsArgumentExceptionWithParameterName(KeyType keyType, int len)
    {
        foreach (var d in CorrectLengthOutOfRangeScalars(len))
        {
            var act = () => Provider.Sign(keyType, d, [1, 2, 3]);
            act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
        }
    }

    [Theory]
    [InlineData(KeyType.P256, 32)]
    [InlineData(KeyType.P384, 48)]
    [InlineData(KeyType.P521, 66)]
    public void FromPrivateKey_Nist_OutOfRangeScalar_ThrowsArgumentExceptionWithParameterName(KeyType keyType, int len)
    {
        foreach (var d in CorrectLengthOutOfRangeScalars(len))
        {
            var act = () => Generator.FromPrivateKey(keyType, d);
            act.Should().Throw<ArgumentException>().WithParameterName("privateKey");
        }
    }

    // D = 0 (all-zero) and D >= n (all-0xFF exceeds every supported curve order), both at the
    // correct byte length so the length guard passes and the range check is what rejects them.
    private static IEnumerable<byte[]> CorrectLengthOutOfRangeScalars(int len)
    {
        yield return new byte[len];
        var max = new byte[len];
        Array.Fill(max, (byte)0xFF);
        yield return max;
    }

    // ── Sanity: valid keys still round-trip after the new guards ──

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.X25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void FromPrivateKey_ValidGeneratedKey_StillRoundTrips(KeyType keyType)
    {
        var generated = Generator.Generate(keyType);
        var restored = Generator.FromPrivateKey(keyType, generated.PrivateKey);
        restored.PublicKey.Should().Equal(generated.PublicKey,
            "the length guards must not reject a freshly generated, correctly-sized private key");
    }

    // ── Low-order Ed25519 → X25519 conversion ──

    [Fact]
    public void DeriveX25519PublicKeyFromEd25519_AllZeroKey_ThrowsArgumentException()
    {
        // The all-zero Ed25519 public key (y = 0) is a low-order point; it maps to the low-order
        // Montgomery u = 1. Before the fix this minted X25519 public key 01 00 … 00; it must now
        // be rejected rather than producing a degenerate, small-subgroup reference.
        var allZero = new byte[32];
        var act = () => Generator.DeriveX25519PublicKeyFromEd25519(allZero);
        act.Should().Throw<ArgumentException>().WithParameterName("ed25519PublicKey");
    }

    [Fact]
    public void DeriveX25519PublicKeyFromEd25519_RealKey_StillSucceeds()
    {
        // A genuine prime-order Ed25519 public key must still convert (no false rejection).
        var ed = Generator.Generate(KeyType.Ed25519);
        var x = Generator.DeriveX25519PublicKeyFromEd25519(ed.PublicKey);
        x.KeyType.Should().Be(KeyType.X25519);
        x.PublicKey.Should().HaveCount(32);
        x.PublicKey.Should().NotEqual(new byte[32], "a real conversion is not the all-zero key");
    }
}
