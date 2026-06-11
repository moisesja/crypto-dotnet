using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using NetCid;

namespace NetCrypto;

/// <summary>
/// Converts between <see cref="KeyPair"/> and JSON Web Key (JWK) representations.
/// </summary>
public static class JwkConverter
{
    /// <summary>Convert a key type and raw public key bytes to a public-only JWK.</summary>
    public static JsonWebKey ToPublicJwk(KeyType keyType, byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        return keyType switch
        {
            KeyType.Ed25519 => CreateOkpJwk("Ed25519", publicKey),
            KeyType.X25519 => CreateOkpJwk("X25519", publicKey),
            KeyType.P256 => CreateEcJwk("P-256", publicKey),
            KeyType.P384 => CreateEcJwk("P-384", publicKey),
            KeyType.P521 => CreateEcJwk("P-521", publicKey),
            KeyType.Secp256k1 => CreateEcJwk("secp256k1", publicKey),
            KeyType.Bls12381G1 => CreateOkpJwk("BLS12381G1", publicKey),
            KeyType.Bls12381G2 => CreateOkpJwk("BLS12381G2", publicKey),
            _ => throw new ArgumentException($"Unsupported key type: {keyType}")
        };
    }

    /// <summary>Convert a KeyPair to a public-only JWK.</summary>
    public static JsonWebKey ToPublicJwk(KeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        return keyPair.KeyType switch
        {
            KeyType.Ed25519 => CreateOkpJwk("Ed25519", keyPair.PublicKey),
            KeyType.X25519 => CreateOkpJwk("X25519", keyPair.PublicKey),
            KeyType.P256 => CreateEcJwk("P-256", keyPair.PublicKey),
            KeyType.P384 => CreateEcJwk("P-384", keyPair.PublicKey),
            KeyType.P521 => CreateEcJwk("P-521", keyPair.PublicKey),
            KeyType.Secp256k1 => CreateEcJwk("secp256k1", keyPair.PublicKey),
            KeyType.Bls12381G1 => CreateOkpJwk("BLS12381G1", keyPair.PublicKey),
            KeyType.Bls12381G2 => CreateOkpJwk("BLS12381G2", keyPair.PublicKey),
            _ => throw new ArgumentException($"Unsupported key type: {keyPair.KeyType}")
        };
    }

    /// <summary>Convert a KeyPair to a JWK that includes private key material.</summary>
    public static JsonWebKey ToPrivateJwk(KeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        var jwk = ToPublicJwk(keyPair);
        jwk.D = Multibase.Encode(keyPair.PrivateKey, MultibaseEncoding.Base64Url, includePrefix: false);
        return jwk;
    }

    /// <summary>
    /// Extract the key type and raw public key bytes from a JWK.
    /// Inverse of ToPublicJwk.
    /// </summary>
    public static (KeyType KeyType, byte[] PublicKey) ExtractPublicKey(JsonWebKey jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        if (jwk.Kty == "OKP")
        {
            var keyType = jwk.Crv switch
            {
                "Ed25519" => KeyType.Ed25519,
                "X25519" => KeyType.X25519,
                "BLS12381G1" => KeyType.Bls12381G1,
                "BLS12381G2" => KeyType.Bls12381G2,
                _ => throw new ArgumentException($"Unsupported OKP curve: {jwk.Crv}")
            };
            var publicKey = Multibase.Decode("u" + jwk.X);
            return (keyType, publicKey);
        }

        if (jwk.Kty == "EC")
        {
            var keyType = jwk.Crv switch
            {
                "P-256" => KeyType.P256,
                "P-384" => KeyType.P384,
                "P-521" => KeyType.P521,
                "secp256k1" => KeyType.Secp256k1,
                _ => throw new ArgumentException($"Unsupported EC curve: {jwk.Crv}")
            };
            var x = Multibase.Decode("u" + jwk.X);
            var y = Multibase.Decode("u" + jwk.Y);

            // Invalid-curve defense (RFC 7518 §6.2.2): reject any (x, y) that is not actually
            // on the stated curve, BEFORE the caller can use these bytes for ECDH. Failing here
            // protects every downstream consumer that does ExtractPublicKey → DeriveSharedSecret.
            EcPointValidator.EnsureOnCurve(keyType, x, y);

            // Reconstruct compressed SEC1 public key: 0x02/0x03 || x
            var prefix = (y[^1] & 1) == 0 ? (byte)0x02 : (byte)0x03;
            var publicKey = new byte[1 + x.Length];
            publicKey[0] = prefix;
            x.CopyTo(publicKey, 1);
            return (keyType, publicKey);
        }

        throw new ArgumentException($"Unsupported JWK key type: {jwk.Kty}");
    }

    private static JsonWebKey CreateOkpJwk(string crv, byte[] publicKey)
    {
        return new JsonWebKey
        {
            Kty = "OKP",
            Crv = crv,
            X = Multibase.Encode(publicKey, MultibaseEncoding.Base64Url, includePrefix: false)
        };
    }

    private static JsonWebKey CreateEcJwk(string crv, byte[] publicKey)
    {
        // Fixed coordinate size per curve — reject wrong-length points up front so we never
        // emit a JWK with truncated or fabricated coordinates (NFR-3; mirrors the validation
        // the consuming ExtractPublicKey path already performs).
        var coordLen = crv switch
        {
            "P-256" or "secp256k1" => 32,
            "P-384" => 48,
            "P-521" => 66,
            _ => throw new ArgumentException($"Unsupported curve: {crv}", nameof(crv))
        };

        byte[] x, y;

        if (publicKey.Length == 1 + coordLen && (publicKey[0] == 0x02 || publicKey[0] == 0x03))
        {
            // Compressed SEC1 point — decompress to get x, y coordinates
            (x, y) = DecompressToCoordinates(crv, publicKey);
        }
        else if (publicKey.Length == 1 + 2 * coordLen && publicKey[0] == 0x04)
        {
            // Uncompressed: 0x04 || x || y
            x = publicKey[1..(1 + coordLen)];
            y = publicKey[(1 + coordLen)..];
            // Defense in depth: ensure the supplied point is actually on the curve before
            // emitting it (the compressed branch derives y from the curve, so it is implied there).
            var keyType = crv switch
            {
                "P-256" => KeyType.P256,
                "P-384" => KeyType.P384,
                "P-521" => KeyType.P521,
                _ => KeyType.Secp256k1
            };
            EcPointValidator.EnsureOnCurve(keyType, x, y);
        }
        else
        {
            throw new ArgumentException(
                $"Invalid EC public key for {crv}: expected {1 + coordLen}-byte compressed (0x02/0x03) " +
                $"or {1 + 2 * coordLen}-byte uncompressed (0x04) SEC1 point, got {publicKey.Length} bytes.",
                nameof(publicKey));
        }

        return new JsonWebKey
        {
            Kty = "EC",
            Crv = crv,
            X = Multibase.Encode(x, MultibaseEncoding.Base64Url, includePrefix: false),
            Y = Multibase.Encode(y, MultibaseEncoding.Base64Url, includePrefix: false)
        };
    }

    private static (byte[] X, byte[] Y) DecompressToCoordinates(string crv, byte[] compressedPoint)
    {
        if (crv == "secp256k1")
            return DefaultCryptoProvider.DecompressSecp256k1Point(compressedPoint);

        var curve = crv switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException($"Unsupported curve for decompression: {crv}")
        };
        var parameters = DefaultCryptoProvider.DecompressEcPoint(compressedPoint, curve);
        return (parameters.Q.X!, parameters.Q.Y!);
    }
}
