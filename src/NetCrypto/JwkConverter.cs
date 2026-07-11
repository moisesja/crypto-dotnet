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
    /// <remarks>
    /// The private key leaves this method as the JWK's base64url <c>d</c> <em>string</em>, which
    /// managed code cannot wipe — only take this egress when a serialized private JWK is genuinely
    /// required. The transient byte copy read from the key pair is zeroized before returning.
    /// </remarks>
    public static JsonWebKey ToPrivateJwk(KeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        var jwk = ToPublicJwk(keyPair);
        var privateKey = keyPair.PrivateKey;
        try
        {
            jwk.D = Multibase.Encode(privateKey, MultibaseEncoding.Base64Url, includePrefix: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
        return jwk;
    }

    /// <summary>
    /// Extract the key type and raw public key bytes from a JWK. Inverse of <see cref="ToPublicJwk(KeyType, byte[])"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>On-curve guarantee.</b> For every EC key type (P-256, P-384, P-521, secp256k1) this method
    /// validates that the supplied <c>(x, y)</c> coordinates actually lie on the stated curve — via
    /// <see cref="EcPointValidator.EnsureOnCurve"/> — <em>before</em> returning, throwing
    /// <see cref="CryptographicException"/> for an off-curve, out-of-range, or identity point. This makes
    /// the import boundary the chokepoint for the invalid-curve defense (RFC 7518 §6.2.2; Antipa et al.,
    /// PKC 2003; Jager–Schwenk–Somorovsky, ESORICS 2015), so a consumer that does
    /// <c>ExtractPublicKey → ICryptoProvider.DeriveSharedSecret</c> on an attacker-supplied JWK (e.g. a
    /// JWE <c>epk</c>) inherits the protection by default and need not remember a separate validation call.
    /// OKP curves (Ed25519, X25519) carry no off-curve points by construction, so the check is a no-op for them.
    /// </para>
    /// </remarks>
    /// <exception cref="CryptographicException">An EC JWK whose coordinates are off-curve, out of range,
    /// or the point at infinity.</exception>
    /// <exception cref="ArgumentException">The JWK is null-coordinate, malformed, or of an unsupported key type/curve.</exception>
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
            var publicKey = DecodeBase64UrlCoordinate(jwk.X, "x");
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
            var x = DecodeBase64UrlCoordinate(jwk.X, "x");
            var y = DecodeBase64UrlCoordinate(jwk.Y, "y");

            // Invalid-curve defense (RFC 7518 §6.2.2): reject any (x, y) that is not actually
            // on the stated curve, BEFORE the caller can use these bytes for ECDH. Failing here
            // protects every downstream consumer that does ExtractPublicKey → DeriveSharedSecret.
            EcPointValidator.EnsureOnCurve(keyType, x, y);

            // Reconstruct compressed SEC1 public key: 0x02/0x03 || x. The coordinate must be
            // left-padded to the curve's fixed field width: EnsureOnCurve compares integer
            // *values*, so a base64url-trimmed leading-zero byte passes validation but would
            // otherwise yield a short (e.g. 32- instead of 33-byte) SEC1 point, breaking the
            // ToPublicJwk → ExtractPublicKey round-trip and every downstream length check.
            var coordLen = CoordinateLength(keyType);
            if (x.Length > coordLen)
                throw new ArgumentException(
                    $"JWK 'x' coordinate is {x.Length} bytes; expected at most {coordLen} for {jwk.Crv}.",
                    nameof(jwk));
            var prefix = (y[^1] & 1) == 0 ? (byte)0x02 : (byte)0x03;
            var publicKey = new byte[1 + coordLen];
            publicKey[0] = prefix;
            x.CopyTo(publicKey.AsSpan(1 + coordLen - x.Length));
            return (keyType, publicKey);
        }

        throw new ArgumentException($"Unsupported JWK key type: {jwk.Kty}");
    }

    private static int CoordinateLength(KeyType keyType) => keyType switch
    {
        KeyType.P256 or KeyType.Secp256k1 => 32,
        KeyType.P384 => 48,
        KeyType.P521 => 66,
        _ => throw new ArgumentException($"No EC coordinate length for key type: {keyType}", nameof(keyType))
    };

    // Decode a JWK base64url coordinate, normalizing a malformed value to ArgumentException
    // (NetCid.Multibase throws CidFormatException : FormatException, which NFR-3 forbids from a
    // public method given untrusted JWK input).
    private static byte[] DecodeBase64UrlCoordinate(string? value, string member)
    {
        const string ParamName = "jwk";
        if (value is null)
            throw new ArgumentException($"JWK is missing the required '{member}' coordinate.", ParamName);
        try
        {
            return Multibase.Decode("u" + value);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException($"JWK '{member}' coordinate is not valid base64url.", ParamName, ex);
        }
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
