using System.Security.Cryptography;
using NBitcoin.Secp256k1;
using NSec.Cryptography;
using Bls = Nethermind.Crypto.Bls;

namespace NetCrypto;

/// <summary>
/// Default implementation of <see cref="IKeyGenerator"/> supporting all key types.
/// </summary>
public sealed class DefaultKeyGenerator : IKeyGenerator
{
    /// <inheritdoc />
    public KeyPair Generate(KeyType keyType)
    {
        return keyType switch
        {
            KeyType.Ed25519 => GenerateEd25519(),
            KeyType.X25519 => GenerateX25519(),
            KeyType.P256 => GenerateEcDsa(ECCurve.NamedCurves.nistP256, KeyType.P256),
            KeyType.P384 => GenerateEcDsa(ECCurve.NamedCurves.nistP384, KeyType.P384),
            KeyType.P521 => GenerateEcDsa(ECCurve.NamedCurves.nistP521, KeyType.P521),
            KeyType.Secp256k1 => GenerateSecp256k1(),
            KeyType.Bls12381G1 or KeyType.Bls12381G2 => GenerateBls(keyType),
            _ => throw new ArgumentException($"Unsupported key type: {keyType}")
        };
    }

    /// <inheritdoc />
    public KeyPair FromPrivateKey(KeyType keyType, ReadOnlySpan<byte> privateKey)
    {
        return keyType switch
        {
            KeyType.Ed25519 => RestoreEd25519(privateKey),
            KeyType.X25519 => RestoreX25519(privateKey),
            KeyType.P256 => RestoreEcDsa(privateKey, ECCurve.NamedCurves.nistP256, KeyType.P256),
            KeyType.P384 => RestoreEcDsa(privateKey, ECCurve.NamedCurves.nistP384, KeyType.P384),
            KeyType.P521 => RestoreEcDsa(privateKey, ECCurve.NamedCurves.nistP521, KeyType.P521),
            KeyType.Secp256k1 => RestoreSecp256k1(privateKey),
            KeyType.Bls12381G1 or KeyType.Bls12381G2 => RestoreBls(keyType, privateKey),
            _ => throw new ArgumentException($"Unsupported key type: {keyType}")
        };
    }

    /// <inheritdoc />
    public PublicKeyReference FromPublicKey(KeyType keyType, ReadOnlySpan<byte> publicKey)
    {
        var raw = publicKey.ToArray();

        // The key model stores canonical encodings only (compressed SEC1 for EC types) — that is
        // what Generate/FromPrivateKey produce and what MultibasePublicKey/JWK conversion assume.
        // Rejecting other lengths here keeps a malformed reference from propagating into
        // did:key/JWK output where it would encode garbage instead of failing.
        if (!keyType.IsValidKeyLength(raw.Length))
            throw new ArgumentException(
                $"Invalid {keyType} public key length: {raw.Length} bytes. The key model stores " +
                "the canonical encoding (compressed SEC1 point for EC types); convert an " +
                "uncompressed EC point with KeyTypeExtensions.NormalizeToCompressed first.",
                nameof(publicKey));

        // Invalid-curve defense for the SEC1 types: a compressed x not on the curve must not
        // become a PublicKeyReference handed to ECDH/verify paths. (No-op for non-EC types.)
        if (!keyType.IsValidEcPoint(raw))
            throw new ArgumentException(
                $"Invalid {keyType} public key: not a valid point on the curve.", nameof(publicKey));

        return new PublicKeyReference
        {
            KeyType = keyType,
            PublicKey = raw
        };
    }

    /// <inheritdoc />
    public KeyPair DeriveX25519FromEd25519(KeyPair ed25519KeyPair)
    {
        ArgumentNullException.ThrowIfNull(ed25519KeyPair);
        if (ed25519KeyPair.KeyType != KeyType.Ed25519)
            throw new ArgumentException("Key pair must be Ed25519.", nameof(ed25519KeyPair));
        // Guard the length here (matching the public-only sibling below) so a wrong-sized seed
        // raises ArgumentException rather than a raw NSec FormatException from Key.Import (NFR-3).
        if (ed25519KeyPair.PrivateKey is not { Length: 32 })
            throw new ArgumentException("Ed25519 private key must be 32 bytes.", nameof(ed25519KeyPair));

        // Use libsodium via NSec: import the Ed25519 key and derive X25519.
        // NSec Key.Import for Ed25519 expects the 32-byte seed.
        var edAlgo = SignatureAlgorithm.Ed25519;
        var xAlgo = NSec.Cryptography.KeyAgreementAlgorithm.X25519;

        using var edKey = Key.Import(edAlgo, ed25519KeyPair.PrivateKey, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        // Convert Ed25519 public key to X25519 public key using the birational map.
        // Ed25519 private key (seed) -> clamp & scalar multiply on Curve25519 basepoint.
        // We use the SHA-512 of the seed, clamp, and use as X25519 private key.
        var edPrivateExpanded = SHA512.HashData(ed25519KeyPair.PrivateKey);
        var x25519PrivateKey = edPrivateExpanded[..32];

        // Clamp the scalar per X25519 spec
        x25519PrivateKey[0] &= 248;
        x25519PrivateKey[31] &= 127;
        x25519PrivateKey[31] |= 64;

        // Import as X25519 private key to derive the public key
        using var xKey = Key.Import(xAlgo, x25519PrivateKey, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return new KeyPair
        {
            KeyType = KeyType.X25519,
            PrivateKey = x25519PrivateKey,
            PublicKey = xKey.PublicKey.Export(KeyBlobFormat.RawPublicKey)
        };
    }

    /// <inheritdoc />
    public PublicKeyReference DeriveX25519PublicKeyFromEd25519(ReadOnlySpan<byte> ed25519PublicKey)
    {
        if (ed25519PublicKey.Length != 32)
            throw new ArgumentException("Ed25519 public key must be 32 bytes.", nameof(ed25519PublicKey));

        // Convert Ed25519 public key (Edwards form) to X25519 public key (Montgomery form).
        // The birational map is: u = (1 + y) / (1 - y) mod p
        // where y is the y-coordinate encoded in the Ed25519 public key (little-endian),
        // and p = 2^255 - 19.
        var yBytes = ed25519PublicKey.ToArray();
        yBytes[31] &= 0x7F; // Clear the sign bit to get y

        var p = System.Numerics.BigInteger.Pow(2, 255) - 19;
        var y = new System.Numerics.BigInteger(yBytes, isUnsigned: true, isBigEndian: false);

        // u = (1 + y) * modInverse(1 - y, p) mod p
        var numerator = (1 + y) % p;
        var denominator = (p + 1 - y) % p; // (1 - y) mod p, ensuring positive
        // y == 1 makes the birational map (u = (1+y)/(1−y)) undefined (Montgomery point at
        // infinity). ModInverse(0) would silently yield u = 0 — a degenerate, low-order X25519
        // point — so reject it instead of emitting garbage from an invalid Ed25519 key.
        if (denominator.IsZero)
            throw new ArgumentException(
                "Ed25519 public key does not map to a valid X25519 point (y = 1).", nameof(ed25519PublicKey));
        var u = numerator * ModInverse(denominator, p) % p;
        if (u < 0) u += p;

        // Reject low-order results. An Ed25519 public key that is itself a small-order point
        // (e.g. the all-zero key, y = 0) maps to a low-order Montgomery u-coordinate; minting a
        // PublicKeyReference for it would hand a degenerate, small-subgroup X25519 key to callers
        // that key-agree with it. The five canonical Curve25519 low-order u-coordinates (orders
        // 1/2/4/8, reduced mod p) are the complete set to exclude (RFC 7748 §6.1 small-subgroup
        // guidance). Legitimate prime-order Ed25519 keys never land here.
        if (LowOrderX25519U.Contains(u))
            throw new ArgumentException(
                "Ed25519 public key maps to a low-order X25519 point.", nameof(ed25519PublicKey));

        // Encode u as 32 bytes little-endian
        var uBytes = u.ToByteArray(isUnsigned: true, isBigEndian: false);
        var result = new byte[32];
        uBytes.AsSpan(0, Math.Min(uBytes.Length, 32)).CopyTo(result);

        return new PublicKeyReference
        {
            KeyType = KeyType.X25519,
            PublicKey = result
        };
    }

    /// <summary>Modular inverse via Fermat's little theorem: a^(p-2) mod p.</summary>
    private static System.Numerics.BigInteger ModInverse(System.Numerics.BigInteger a, System.Numerics.BigInteger m)
        => System.Numerics.BigInteger.ModPow(a, m - 2, m);

    // The canonical Curve25519 low-order point u-coordinates (points of order 1, 2, 4, and 8),
    // reduced mod p = 2^255 − 19. Any derived u in this set is a small-subgroup point and must be
    // rejected. (p and p+1 reduce to 0 and 1, already listed.)
    private static readonly System.Numerics.BigInteger X25519Prime =
        System.Numerics.BigInteger.Pow(2, 255) - 19;
    private static readonly HashSet<System.Numerics.BigInteger> LowOrderX25519U =
    [
        System.Numerics.BigInteger.Zero,
        System.Numerics.BigInteger.One,
        System.Numerics.BigInteger.Parse("325606250916557431795983626356110631294008115727848805560023387167927233504"),
        System.Numerics.BigInteger.Parse("39382357235489614581723060781553021112529911719440698176882885853963445705823"),
        X25519Prime - 1,
    ];

    // --- Ed25519 ---

    private static KeyPair GenerateEd25519()
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Create(algorithm,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return new KeyPair
        {
            KeyType = KeyType.Ed25519,
            PrivateKey = key.Export(KeyBlobFormat.RawPrivateKey),
            PublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey)
        };
    }

    private static KeyPair RestoreEd25519(ReadOnlySpan<byte> privateKey)
    {
        // Guard before NSec (raw FormatException on a wrong-length blob) → ArgumentException (NFR-3).
        RawKeyGuard.RequireLength(privateKey, 32, nameof(privateKey), "Ed25519 private key");

        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return new KeyPair
        {
            KeyType = KeyType.Ed25519,
            PrivateKey = privateKey.ToArray(),
            PublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey)
        };
    }

    // --- X25519 ---

    private static KeyPair GenerateX25519()
    {
        var algorithm = NSec.Cryptography.KeyAgreementAlgorithm.X25519;
        using var key = Key.Create(algorithm,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return new KeyPair
        {
            KeyType = KeyType.X25519,
            PrivateKey = key.Export(KeyBlobFormat.RawPrivateKey),
            PublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey)
        };
    }

    private static KeyPair RestoreX25519(ReadOnlySpan<byte> privateKey)
    {
        RawKeyGuard.RequireLength(privateKey, 32, nameof(privateKey), "X25519 private key");

        var algorithm = NSec.Cryptography.KeyAgreementAlgorithm.X25519;
        using var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return new KeyPair
        {
            KeyType = KeyType.X25519,
            PrivateKey = privateKey.ToArray(),
            PublicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey)
        };
    }

    // --- P-256 / P-384 ---

    private static KeyPair GenerateEcDsa(ECCurve curve, KeyType keyType)
    {
        using var ecdsa = ECDsa.Create(curve);
        var parameters = ecdsa.ExportParameters(true);

        // Public key as compressed SEC1 point: 0x02 (even Y) or 0x03 (odd Y) || X
        var prefix = (parameters.Q.Y![^1] & 1) == 0 ? (byte)0x02 : (byte)0x03;
        var publicKey = new byte[1 + parameters.Q.X!.Length];
        publicKey[0] = prefix;
        parameters.Q.X.CopyTo(publicKey, 1);

        return new KeyPair
        {
            KeyType = keyType,
            PrivateKey = parameters.D!,
            PublicKey = publicKey
        };
    }

    private static KeyPair RestoreEcDsa(ReadOnlySpan<byte> privateKey, ECCurve curve, KeyType keyType)
    {
        using var ecdsa = ECDsa.Create();
        var importParams = DefaultCryptoProvider.ImportEcPrivateKey(privateKey, curve);
        ecdsa.ImportParameters(importParams);

        var parameters = ecdsa.ExportParameters(false);

        var prefix = (parameters.Q.Y![^1] & 1) == 0 ? (byte)0x02 : (byte)0x03;
        var publicKey = new byte[1 + parameters.Q.X!.Length];
        publicKey[0] = prefix;
        parameters.Q.X.CopyTo(publicKey, 1);

        return new KeyPair
        {
            KeyType = keyType,
            PrivateKey = privateKey.ToArray(),
            PublicKey = publicKey
        };
    }

    // --- secp256k1 ---

    private static KeyPair GenerateSecp256k1()
    {
        ECPrivKey? privKey = null;
        Span<byte> keyBytes = stackalloc byte[32];

        while (privKey is null)
        {
            RandomNumberGenerator.Fill(keyBytes);
            ECPrivKey.TryCreate(keyBytes, out privKey);
        }

        var pubKey = privKey.CreatePubKey();

        // Store compressed public key (33 bytes)
        var publicKeyBytes = new byte[33];
        pubKey.WriteToSpan(compressed: true, publicKeyBytes, out _);

        var privateKeyBytes = new byte[32];
        privKey.WriteToSpan(privateKeyBytes);

        return new KeyPair
        {
            KeyType = KeyType.Secp256k1,
            PrivateKey = privateKeyBytes,
            PublicKey = publicKeyBytes
        };
    }

    private static KeyPair RestoreSecp256k1(ReadOnlySpan<byte> privateKey)
    {
        // Validate length before handing to NBitcoin, whose ctor indexes a 32-byte span
        // and would otherwise throw IndexOutOfRangeException on bad input (NFR-3).
        if (privateKey.Length != 32)
            throw new ArgumentException("secp256k1 private key must be 32 bytes.", nameof(privateKey));
        if (!ECPrivKey.TryCreate(privateKey, out var privKey) || privKey is null)
            throw new ArgumentException("Invalid secp256k1 private key.", nameof(privateKey));
        var pubKey = privKey.CreatePubKey();

        var publicKeyBytes = new byte[33];
        pubKey.WriteToSpan(compressed: true, publicKeyBytes, out _);

        return new KeyPair
        {
            KeyType = KeyType.Secp256k1,
            PrivateKey = privateKey.ToArray(),
            PublicKey = publicKeyBytes
        };
    }

    // --- BLS12-381 ---

    private static KeyPair GenerateBls(KeyType keyType)
    {
        // Generate 32 bytes of random IKM, then use blst keygen
        Span<byte> ikm = stackalloc byte[32];
        RandomNumberGenerator.Fill(ikm);

        var sk = new Bls.SecretKey();
        sk.Keygen(ikm);

        return BuildBlsKeyPair(keyType, sk);
    }

    private static KeyPair RestoreBls(KeyType keyType, ReadOnlySpan<byte> privateKey)
    {
        // FromBendian throws BlsException on a wrong-length/invalid scalar; normalize to a
        // parameter-named ArgumentException (NFR-3), matching SignBls.
        RawKeyGuard.RequireLength(privateKey, 32, nameof(privateKey), "BLS12-381 private key");

        var sk = new Bls.SecretKey();
        try
        {
            sk.FromBendian(privateKey);
        }
        catch (Bls.BlsException ex)
        {
            throw new ArgumentException("Invalid BLS12-381 private key.", nameof(privateKey), ex);
        }

        return BuildBlsKeyPair(keyType, sk);
    }

    private static KeyPair BuildBlsKeyPair(KeyType keyType, Bls.SecretKey sk)
    {
        byte[] publicKey;
        if (keyType == KeyType.Bls12381G1)
        {
            // G1 public key: 48 bytes compressed
            var pk = new Bls.P1();
            pk.FromSk(sk);
            publicKey = pk.Compress();
        }
        else
        {
            // G2 public key: 96 bytes compressed
            // P2 doesn't have FromSk — use scalar multiplication on the generator
            var scalar = new Bls.Scalar();
            scalar.FromBendian(sk.ToBendian());
            var pk = Bls.P2.Generator().Mult(scalar);
            publicKey = pk.Compress();
        }

        return new KeyPair
        {
            KeyType = keyType,
            PrivateKey = sk.ToBendian(),
            PublicKey = publicKey
        };
    }
}
