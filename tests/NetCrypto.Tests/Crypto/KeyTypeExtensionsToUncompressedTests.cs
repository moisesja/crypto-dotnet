using System.Security.Cryptography;
using FluentAssertions;

namespace NetCrypto.Tests.Crypto;

/// <summary>
/// Issue #19 — public compressed → uncompressed EC point decompression.
/// <see cref="KeyTypeExtensions.ToUncompressed"/> must produce a validated
/// <c>0x04 ‖ X ‖ Y</c> encoding from a bare compressed SEC1 point (no signature required),
/// and reject every malformed or off-curve input with a parameter-named ArgumentException.
/// </summary>
public class KeyTypeExtensionsToUncompressedTests
{
    private readonly DefaultKeyGenerator _keyGen = new();

    private static int CoordLen(KeyType keyType) => keyType switch
    {
        KeyType.P256 => 32,
        KeyType.P384 => 48,
        KeyType.P521 => 66,
        KeyType.Secp256k1 => 32,
        _ => throw new ArgumentOutOfRangeException(nameof(keyType)),
    };

    // -------- Happy path: decompression round-trips --------

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    public void ToUncompressed_GeneratedCompressedKey_RoundTripsThroughNormalizeToCompressed(KeyType keyType)
    {
        var keyPair = _keyGen.Generate(keyType);
        var coordLen = CoordLen(keyType);

        var uncompressed = keyType.ToUncompressed(keyPair.PublicKey);

        uncompressed.Length.Should().Be(1 + 2 * coordLen);
        uncompressed[0].Should().Be(0x04);
        // The inverse operation must land exactly on the canonical compressed encoding.
        keyType.NormalizeToCompressed(uncompressed).Should().Equal(keyPair.PublicKey);
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    public void ToUncompressed_NistCurves_MatchesBclCoordinates(KeyType keyType)
    {
        // The BCL is an independent oracle: export explicit (X, Y), compress with
        // NormalizeToCompressed, and require ToUncompressed to recover the exact coordinates.
        var curve = keyType switch
        {
            KeyType.P256 => ECCurve.NamedCurves.nistP256,
            KeyType.P384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        var coordLen = CoordLen(keyType);

        using var ecdsa = ECDsa.Create(curve);
        var q = ecdsa.ExportParameters(includePrivateParameters: false).Q;

        var expected = new byte[1 + 2 * coordLen];
        expected[0] = 0x04;
        // BCL coordinates are fixed-width for the curve; copy right-aligned to be explicit.
        q.X!.CopyTo(expected, 1 + coordLen - q.X!.Length);
        q.Y!.CopyTo(expected, 1 + 2 * coordLen - q.Y!.Length);

        var compressed = keyType.NormalizeToCompressed(expected);

        keyType.ToUncompressed(compressed).Should().Equal(expected);
    }

    [Fact]
    public void ToUncompressed_Secp256k1GeneratorPoint_MatchesSec2Vector()
    {
        // SEC 2 v2 §2.4.1 — the secp256k1 base point G.
        var gx = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        var gy = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
        var compressedG = Convert.FromHexString("02" + gx); // Gy is even → 0x02 prefix

        var uncompressed = KeyType.Secp256k1.ToUncompressed(compressedG);

        Convert.ToHexString(uncompressed).Should().Be("04" + gx + gy);
    }

    [Fact]
    public void ToUncompressed_AgreesWithRecoverPublicKey_TheDidEthrUseCase()
    {
        // The consumer scenario from issue #19: derive an Ethereum address from a *bare*
        // compressed public key. The result must be byte-identical to the uncompressed key the
        // recoverable-signature path produces, and yield the same keccak256(X ‖ Y)[12..] address.
        var keyPair = _keyGen.Generate(KeyType.Secp256k1);
        var digest = Keccak256.Hash("issue #19"u8);
        var (signature, recoveryId) = keyPair.WithPrivateKey(
            pk => Secp256k1Recoverable.Sign(pk, digest));

        var fromBareKey = KeyType.Secp256k1.ToUncompressed(keyPair.PublicKey);
        var fromRecovery = Secp256k1Recoverable.RecoverPublicKey(digest, signature, recoveryId, compressed: false);

        fromBareKey.Should().Equal(fromRecovery);
        Keccak256.Hash(fromBareKey.AsSpan(1))[12..]
            .Should().Equal(Keccak256.Hash(fromRecovery.AsSpan(1))[12..], "both paths must derive the same address");
    }

    // -------- Happy path: uncompressed pass-through --------

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    public void ToUncompressed_UncompressedInput_IsValidatedPassThroughCopy(KeyType keyType)
    {
        var keyPair = _keyGen.Generate(keyType);
        var uncompressed = keyType.ToUncompressed(keyPair.PublicKey);

        var passedThrough = keyType.ToUncompressed(uncompressed);

        passedThrough.Should().Equal(uncompressed);
        // A defensive copy: mutating the result must not corrupt the caller's input array.
        passedThrough.Should().NotBeSameAs(uncompressed);
    }

    // -------- Negatives: absent / wrong-shape input (NFR-3 families a, b) --------

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.Secp256k1)]
    public void ToUncompressed_NullPublicKey_ThrowsArgumentNullException(KeyType keyType)
    {
        var act = () => keyType.ToUncompressed(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("publicKey");
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.X25519)]
    [InlineData(KeyType.Bls12381G1)]
    [InlineData(KeyType.Bls12381G2)]
    public void ToUncompressed_NonSec1KeyType_ThrowsArgumentException(KeyType keyType)
    {
        var act = () => keyType.ToUncompressed(new byte[33]);
        act.Should().Throw<ArgumentException>().WithParameterName("keyType");
    }

    [Theory]
    [InlineData(KeyType.P256, 0)]
    [InlineData(KeyType.P256, 32)]   // coordinate without prefix
    [InlineData(KeyType.P256, 34)]   // off-by-one compressed
    [InlineData(KeyType.P256, 64)]   // X ‖ Y without prefix
    [InlineData(KeyType.P256, 66)]   // off-by-one uncompressed
    [InlineData(KeyType.P384, 33)]   // valid length for the *wrong* curve
    [InlineData(KeyType.P521, 49)]   // valid length for the *wrong* curve
    [InlineData(KeyType.Secp256k1, 0)]
    [InlineData(KeyType.Secp256k1, 32)]
    [InlineData(KeyType.Secp256k1, 34)]
    [InlineData(KeyType.Secp256k1, 64)]
    public void ToUncompressed_WrongLength_ThrowsArgumentException(KeyType keyType, int length)
    {
        // 0x02 prefix so only the length is wrong, not the prefix byte.
        var bytes = new byte[length];
        if (length > 0) bytes[0] = 0x02;

        var act = () => keyType.ToUncompressed(bytes);
        act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.Secp256k1)]
    public void ToUncompressed_WrongPrefix_ThrowsArgumentException(KeyType keyType)
    {
        var keyPair = _keyGen.Generate(keyType);

        // Compressed length with an uncompressed prefix, and vice versa; plus a junk prefix.
        var compressedWith04 = (byte[])keyPair.PublicKey.Clone();
        compressedWith04[0] = 0x04;
        var uncompressedWith02 = keyType.ToUncompressed(keyPair.PublicKey);
        uncompressedWith02[0] = 0x02;
        var junkPrefix = (byte[])keyPair.PublicKey.Clone();
        junkPrefix[0] = 0x05;

        foreach (var bad in new[] { compressedWith04, uncompressedWith02, junkPrefix })
        {
            var act = () => keyType.ToUncompressed(bad);
            act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
        }
    }

    // -------- Negatives: structurally-valid-but-semantically-wrong (NFR-3 family c) --------

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    public void ToUncompressed_CompressedXWithNoCurveSolution_ThrowsArgumentException(KeyType keyType)
    {
        // Roughly half of all field elements are not the X of any curve point. Walk small X
        // values until one is rejected — it must surface as ArgumentException, never a leaked
        // CryptographicException or a silently fabricated off-curve point.
        var coordLen = CoordLen(keyType);
        var found = false;
        for (byte x = 1; x <= 100 && !found; x++)
        {
            var candidate = new byte[coordLen + 1];
            candidate[0] = 0x02;
            candidate[^1] = x;
            try
            {
                var result = keyType.ToUncompressed(candidate);
                // Accepted → must be a genuine on-curve point (defense-in-depth cross-check).
                keyType.IsValidEcPoint(result).Should().BeTrue(
                    $"x={x} was accepted so its decompression must be on-curve");
            }
            catch (ArgumentException ex)
            {
                ex.ParamName.Should().Be("publicKey");
                found = true;
            }
        }

        found.Should().BeTrue("some x in [1,100] must have no curve solution");
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    public void ToUncompressed_OffCurveUncompressedInput_ThrowsArgumentException(KeyType keyType)
    {
        // (x, y) = (1, 1) is on none of the supported curves. The tolerant pass-through must
        // still validate — accepting this would hand consumers an invalid-curve-attack vector.
        var coordLen = CoordLen(keyType);
        var offCurve = new byte[1 + 2 * coordLen];
        offCurve[0] = 0x04;
        offCurve[coordLen] = 0x01;      // x = 1
        offCurve[2 * coordLen] = 0x01;  // y = 1

        var act = () => keyType.ToUncompressed(offCurve);
        act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    [InlineData(KeyType.Secp256k1)]
    public void ToUncompressed_HybridSec1Encoding_ThrowsArgumentException(KeyType keyType)
    {
        // SEC1 also defines *hybrid* encodings (0x06/0x07 ‖ X ‖ Y, parity in the prefix). The
        // documented grammar is compressed-or-uncompressed only; a hybrid form of a perfectly
        // valid point must be rejected, not silently canonicalized (one point, one wire form).
        var keyPair = _keyGen.Generate(keyType);
        var hybrid = keyType.ToUncompressed(keyPair.PublicKey);
        hybrid[0] = (byte)((hybrid[^1] & 1) == 0 ? 0x06 : 0x07); // parity-correct hybrid prefix

        var act = () => keyType.ToUncompressed(hybrid);
        act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
    }

    [Theory]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.Secp256k1)]
    public void ToUncompressed_PointAtInfinityEncoding_ThrowsArgumentException(KeyType keyType)
    {
        // All-zero coordinates under a 0x04 prefix encode the identity — not a public key.
        var coordLen = CoordLen(keyType);
        var identity = new byte[1 + 2 * coordLen];
        identity[0] = 0x04;

        var act = () => keyType.ToUncompressed(identity);
        act.Should().Throw<ArgumentException>().WithParameterName("publicKey");
    }
}
