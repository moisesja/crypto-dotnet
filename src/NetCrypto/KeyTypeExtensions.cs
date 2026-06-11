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

    private static bool ValidateNistPoint(byte[] rawKey, ECCurve curve)
    {
        // ImportEcPublicKey runs EcPointValidator on the (decompressed) point and throws if it is
        // off-curve, so a successful import is proof the point is valid. The caller turns the throw
        // into a false via its surrounding try/catch.
        DefaultCryptoProvider.ImportEcPublicKey(rawKey, curve);
        return true;
    }
}
