using System.Security.Cryptography;
using NBitcoin.Secp256k1;
using NetCid;

namespace NetCrypto;

/// <summary>
/// Maps <see cref="KeyType"/> to/from multicodec code values defined in <see cref="Multicodec"/>.
/// </summary>
public static class KeyTypeExtensions
{
    private static readonly Dictionary<KeyType, ulong> CodeByKeyType = new()
    {
        [KeyType.Ed25519] = Multicodec.Ed25519Pub,
        [KeyType.X25519] = Multicodec.X25519Pub,
        [KeyType.P256] = Multicodec.P256Pub,
        [KeyType.P384] = Multicodec.P384Pub,
        [KeyType.P521] = Multicodec.P521Pub,
        [KeyType.Secp256k1] = Multicodec.Secp256k1Pub,
        [KeyType.Bls12381G1] = Multicodec.Bls12381G1Pub,
        [KeyType.Bls12381G2] = Multicodec.Bls12381G2Pub,
    };

    private static readonly Dictionary<ulong, KeyType> KeyTypeByCode =
        CodeByKeyType.ToDictionary(kv => kv.Value, kv => kv.Key);

    /// <summary>Get the multicodec code for a key type.</summary>
    public static ulong GetMulticodec(this KeyType keyType) =>
        CodeByKeyType.TryGetValue(keyType, out var code)
            ? code
            : throw new ArgumentException($"Unsupported key type: {keyType}", nameof(keyType));

    /// <summary>Resolve a multicodec code to a <see cref="KeyType"/>.</summary>
    public static KeyType FromMulticodec(ulong codec) =>
        KeyTypeByCode.TryGetValue(codec, out var keyType)
            ? keyType
            : throw new ArgumentException($"Unknown multicodec: 0x{codec:X}");

    /// <summary>
    /// Validates that raw key bytes have the expected length for the given key type.
    /// Returns true if valid.
    /// </summary>
    public static bool IsValidKeyLength(this KeyType keyType, int length) => keyType switch
    {
        KeyType.Ed25519 => length == 32,
        KeyType.X25519 => length == 32,
        KeyType.P256 => length == 33,       // compressed SEC1 point
        KeyType.P384 => length == 49,       // compressed SEC1 point
        KeyType.P521 => length == 67,       // compressed SEC1 point (1 + 66, ceil(521/8) = 66)
        KeyType.Secp256k1 => length == 33,  // compressed SEC1 point
        KeyType.Bls12381G1 => length == 48,
        KeyType.Bls12381G2 => length == 96,
        _ => false
    };

    /// <summary>
    /// Normalizes an EC public key to compressed SEC1 format for key types that require it.
    /// Uncompressed keys (0x04 prefix, 65/97 bytes) are compressed to 33/49 bytes.
    /// Keys that are already compressed or non-EC keys are returned as-is.
    /// </summary>
    public static byte[] NormalizeToCompressed(this KeyType keyType, byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        switch (keyType)
        {
            case KeyType.P256 when publicKey.Length == 65 && publicKey[0] == 0x04:
                return CompressNistPoint(publicKey, 32);

            case KeyType.P384 when publicKey.Length == 97 && publicKey[0] == 0x04:
                return CompressNistPoint(publicKey, 48);

            case KeyType.P521 when publicKey.Length == 133 && publicKey[0] == 0x04:
                return CompressNistPoint(publicKey, 66);

            case KeyType.Secp256k1 when publicKey.Length == 65 && publicKey[0] == 0x04:
            {
                if (!ECPubKey.TryCreate(publicKey, null, out _, out var pubKey))
                    throw new ArgumentException("Invalid secp256k1 uncompressed public key.");
                var compressed = new byte[33];
                pubKey.WriteToSpan(compressed: true, compressed, out _);
                return compressed;
            }

            default:
                return publicKey;
        }
    }

    /// <summary>
    /// Decompresses an EC public key to uncompressed SEC1 format (<c>0x04 ‖ X ‖ Y</c>) — the
    /// inverse of <see cref="NormalizeToCompressed"/>. Compressed input (0x02/0x03 prefix) is
    /// decompressed; already-uncompressed input is validated on-curve and returned as a copy.
    /// Supported for P-256, P-384, P-521, and secp256k1; other key types have no SEC1 point
    /// encoding and are rejected.
    /// </summary>
    /// <param name="keyType">An EC key type (P-256, P-384, P-521, or secp256k1).</param>
    /// <param name="publicKey">Compressed (33/49/67-byte) or uncompressed (65/97/133-byte) SEC1 point.</param>
    /// <returns>The uncompressed SEC1 encoding, 65/97/133 bytes with a 0x04 prefix.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="publicKey"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="keyType"/> is not an EC type, or
    /// <paramref name="publicKey"/> has an invalid length/prefix or is not a point on the curve.</exception>
    public static byte[] ToUncompressed(this KeyType keyType, byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        return keyType switch
        {
            KeyType.P256 => ToUncompressedNist(keyType, publicKey, ECCurve.NamedCurves.nistP256, 32),
            KeyType.P384 => ToUncompressedNist(keyType, publicKey, ECCurve.NamedCurves.nistP384, 48),
            KeyType.P521 => ToUncompressedNist(keyType, publicKey, ECCurve.NamedCurves.nistP521, 66),
            KeyType.Secp256k1 => ToUncompressedSecp256k1(publicKey),
            _ => throw new ArgumentException(
                $"Key type {keyType} has no SEC1 point encoding to decompress.", nameof(keyType)),
        };
    }

    /// <summary>
    /// Validates that an EC public key represents a point on the expected curve.
    /// For non-EC key types, always returns true (validation is length-only).
    /// </summary>
    public static bool IsValidEcPoint(this KeyType keyType, byte[] rawKey)
    {
        try
        {
            switch (keyType)
            {
                case KeyType.P256:
                    return ValidateNistPoint(rawKey, ECCurve.NamedCurves.nistP256);
                case KeyType.P384:
                    return ValidateNistPoint(rawKey, ECCurve.NamedCurves.nistP384);
                case KeyType.P521:
                    return ValidateNistPoint(rawKey, ECCurve.NamedCurves.nistP521);
                case KeyType.Secp256k1:
                    return ECPubKey.TryCreate(rawKey, null, out _, out _);
                default:
                    return true; // Non-EC types: no point validation needed
            }
        }
        catch
        {
            return false;
        }
    }

    private static byte[] CompressNistPoint(byte[] uncompressed, int coordLen)
    {
        // uncompressed: 0x04 || x || y
        var compressed = new byte[coordLen + 1];
        var yLastByte = uncompressed[uncompressed.Length - 1];
        compressed[0] = (byte)((yLastByte & 1) == 0 ? 0x02 : 0x03);
        Buffer.BlockCopy(uncompressed, 1, compressed, 1, coordLen);
        return compressed;
    }

    private static byte[] ToUncompressedSecp256k1(byte[] publicKey)
    {
        // Explicit length/prefix gate so a malformed buffer gets the contractual ArgumentException
        // (NFR-3) and so the accepted grammar stays exactly the documented one — NBitcoin's parser
        // would also take SEC1 *hybrid* encodings (0x06/0x07), which the NIST path rejects.
        // TryCreate then both validates the point is on the curve and canonically re-encodes.
        var wellFormed = publicKey.Length switch
        {
            33 => publicKey[0] is 0x02 or 0x03,
            65 => publicKey[0] == 0x04,
            _ => false,
        };
        if (!wellFormed || !ECPubKey.TryCreate(publicKey, null, out _, out var pubKey))
        {
            throw new ArgumentException("Invalid secp256k1 public key: expected a valid 33-byte " +
                "compressed or 65-byte uncompressed SEC1 point.", nameof(publicKey));
        }

        var uncompressed = new byte[65];
        pubKey.WriteToSpan(compressed: false, uncompressed, out _);
        return uncompressed;
    }

    private static byte[] ToUncompressedNist(KeyType keyType, byte[] publicKey, ECCurve curve, int coordLen)
    {
        // Compressed input: recover Y via the internal decompressor, which validates the
        // resulting point against the curve equation before returning.
        if (publicKey.Length == coordLen + 1 && publicKey[0] is 0x02 or 0x03)
        {
            ECParameters parameters;
            try
            {
                parameters = DefaultCryptoProvider.DecompressEcPoint(publicKey, curve);
            }
            catch (CryptographicException ex)
            {
                // X with no square-root solution (off-curve). Surface the NFR-3 contract type.
                throw new ArgumentException(
                    $"Invalid compressed {keyType} public key: not a point on the curve.",
                    nameof(publicKey), ex);
            }

            var uncompressed = new byte[1 + 2 * coordLen];
            uncompressed[0] = 0x04;
            parameters.Q.X!.CopyTo(uncompressed, 1);
            parameters.Q.Y!.CopyTo(uncompressed, 1 + coordLen);
            return uncompressed;
        }

        // Uncompressed input: validated pass-through (mirrors NormalizeToCompressed's tolerant
        // input handling, but never lets an off-curve point through unchecked).
        if (publicKey.Length == 1 + 2 * coordLen && publicKey[0] == 0x04)
        {
            try
            {
                EcPointValidator.EnsureOnCurve(
                    keyType, publicKey.AsSpan(1, coordLen), publicKey.AsSpan(1 + coordLen));
            }
            catch (CryptographicException ex)
            {
                throw new ArgumentException(
                    $"Invalid uncompressed {keyType} public key: not a point on the curve.",
                    nameof(publicKey), ex);
            }

            return (byte[])publicKey.Clone();
        }

        throw new ArgumentException(
            $"Invalid {keyType} public key: expected a {coordLen + 1}-byte compressed (0x02/0x03) " +
            $"or {1 + 2 * coordLen}-byte uncompressed (0x04) SEC1 point, got {publicKey.Length} bytes.",
            nameof(publicKey));
    }

    private static bool ValidateNistPoint(byte[] rawKey, ECCurve curve)
    {
        // ImportEcPublicKey runs EcPointValidator on the (decompressed) point and throws if it is
        // off-curve, so a successful import is proof the point is valid. The caller turns the throw
        // into a false via its surrounding try/catch.
        DefaultCryptoProvider.ImportEcPublicKey(rawKey, curve);
        return true;
    }
}
