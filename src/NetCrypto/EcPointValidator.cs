using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace NetCrypto;

/// <summary>
/// Validates that an EC public key represents a point on the stated curve. This is the
/// defense against the invalid-curve attack (Antipa et al., PKC 2003; Jager–Schwenk–Somorovsky,
/// ESORICS 2015 — JOSE/JWE variant) whereby a malicious peer sends off-curve `(x, y)` coordinates
/// during ECDH and recovers the victim's static private key bit-by-bit.
/// </summary>
/// <remarks>
/// RFC 7518 §6.2.2 requires implementations to validate `epk` against the stated curve before
/// key agreement. Curve25519/Ed25519 do not need this — all encoded points are on-curve — so
/// this validator only applies to NIST curves (P-256, P-384, P-521) and secp256k1. All four have
/// cofactor 1, so a point on the curve is automatically in the prime-order subgroup.
/// <para>
/// <see cref="EnsureOnCurve"/> is the public EC point-validation entry point; it takes
/// already-decompressed coordinates because on-curve validation does not require point
/// <em>decompression</em>. To recover Y from a compressed SEC1 point, use
/// <see cref="KeyTypeExtensions.ToUncompressed"/>, which validates the resulting point.
/// </para>
/// </remarks>
public static class EcPointValidator
{
    // secp256k1: p = 2^256 − 2^32 − 977, a = 0, b = 7. The NIST primes live in DefaultCryptoProvider
    // (reachable via GetCurveParams); secp256k1 is never an ECCurve in this codebase, so its prime
    // is defined here. The leading 0 keeps BigInteger non-negative under NumberStyles.HexNumber.
    private static readonly BigInteger Secp256k1Prime = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", NumberStyles.HexNumber);

    /// <summary>
    /// Throws <see cref="CryptographicException"/> if <paramref name="x"/> and <paramref name="y"/>
    /// do not represent a valid public-key point on the curve for <paramref name="keyType"/>.
    /// Non-EC key types are a no-op.
    /// </summary>
    /// <param name="keyType">An EC key type (P-256, P-384, P-521, or secp256k1).</param>
    /// <param name="x">Big-endian X coordinate. Zero-pads accepted.</param>
    /// <param name="y">Big-endian Y coordinate. Zero-pads accepted.</param>
    /// <exception cref="CryptographicException">If any coordinate is out of range, both are zero
    /// (point at infinity), or the point does not satisfy the curve equation.</exception>
    public static void EnsureOnCurve(KeyType keyType, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        switch (keyType)
        {
            case KeyType.P256:
                EnsureOnNistCurve(ECCurve.NamedCurves.nistP256, x, y);
                break;
            case KeyType.P384:
                EnsureOnNistCurve(ECCurve.NamedCurves.nistP384, x, y);
                break;
            case KeyType.P521:
                EnsureOnNistCurve(ECCurve.NamedCurves.nistP521, x, y);
                break;
            case KeyType.Secp256k1:
                EnsureSatisfiesCurve(
                    new BigInteger(x, isUnsigned: true, isBigEndian: true),
                    new BigInteger(y, isUnsigned: true, isBigEndian: true),
                    Secp256k1Prime, a: BigInteger.Zero, b: 7);
                break;
            // Non-EC types carry no curve point to validate.
        }
    }

    /// <summary>
    /// On-curve check for a NIST curve, using the shared parameters from
    /// <see cref="DefaultCryptoProvider.GetCurveParams"/>. Lets the internal import/decompress paths
    /// validate directly from an <see cref="ECCurve"/> without bouncing through <see cref="KeyType"/>.
    /// </summary>
    internal static void EnsureOnNistCurve(ECCurve curve, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        var (p, b) = DefaultCryptoProvider.GetCurveParams(curve);
        EnsureSatisfiesCurve(
            new BigInteger(x, isUnsigned: true, isBigEndian: true),
            new BigInteger(y, isUnsigned: true, isBigEndian: true),
            p, a: p - 3, b); // a = -3 for the NIST short-Weierstrass curves
    }

    /// <summary>
    /// Asserts (x, y) satisfies y² ≡ x³ + a·x + b (mod p) along with the range and
    /// point-at-infinity checks. <see cref="DefaultCryptoProvider.DecompressEcPoint"/> calls this
    /// directly with the right-hand side it already computed to derive y, avoiding a recompute.
    /// </summary>
    internal static void EnsureMatchesRhs(BigInteger x, BigInteger y, BigInteger rhs, BigInteger p)
    {
        if (x >= p || y >= p)
            throw new CryptographicException("EC public key coordinate is out of range for the stated curve.");

        if (x.IsZero && y.IsZero)
            throw new CryptographicException("EC public key is the identity (point at infinity).");

        if (BigInteger.ModPow(y, 2, p) != rhs)
            throw new CryptographicException("EC public key is not on the stated curve.");
    }

    private static void EnsureSatisfiesCurve(BigInteger x, BigInteger y, BigInteger p, BigInteger a, BigInteger b)
    {
        var rhs = (BigInteger.ModPow(x, 3, p) + (a * x) % p + b) % p;
        EnsureMatchesRhs(x, y, rhs, p);
    }
}
