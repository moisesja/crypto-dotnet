using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using NBitcoin.Secp256k1;
using NSec.Cryptography;
using Bls = Nethermind.Crypto.Bls;
using SHA256 = System.Security.Cryptography.SHA256;

namespace NetCrypto;

/// <summary>
/// Default implementation of <see cref="ICryptoProvider"/> supporting Ed25519, X25519,
/// P-256, P-384, P-521, secp256k1, and BLS12-381 G1/G2.
/// </summary>
public sealed class DefaultCryptoProvider : ICryptoProvider
{
    public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
        => Sign(keyType, privateKey, data, EcdsaSignatureFormat.Der);

    public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, EcdsaSignatureFormat format)
    {
        var ecFormat = ToDsaFormat(format);
        return keyType switch
        {
            KeyType.Ed25519 => SignEd25519(privateKey, data),
            KeyType.P256 => SignEcDsa(privateKey, data, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, ecFormat),
            KeyType.P384 => SignEcDsa(privateKey, data, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, ecFormat),
            KeyType.P521 => SignEcDsa(privateKey, data, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, ecFormat),
            KeyType.Secp256k1 => SignSecp256k1(privateKey, data),
            KeyType.X25519 => throw new ArgumentException("X25519 is a key agreement algorithm, not a signing algorithm."),
            KeyType.Bls12381G1 or KeyType.Bls12381G2 => SignBls(keyType, privateKey, data),
            _ => throw new ArgumentException($"Unsupported key type for signing: {keyType}")
        };
    }

    public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        => Verify(keyType, publicKey, data, signature, EcdsaSignatureFormat.Der);

    public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format)
    {
        var ecFormat = ToDsaFormat(format);
        return keyType switch
        {
            KeyType.Ed25519 => VerifyEd25519(publicKey, data, signature),
            KeyType.P256 => VerifyEcDsa(publicKey, data, signature, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, ecFormat),
            KeyType.P384 => VerifyEcDsa(publicKey, data, signature, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, ecFormat),
            KeyType.P521 => VerifyEcDsa(publicKey, data, signature, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, ecFormat),
            KeyType.Secp256k1 => VerifySecp256k1(publicKey, data, signature),
            KeyType.X25519 => throw new ArgumentException("X25519 is a key agreement algorithm, not a verification algorithm."),
            KeyType.Bls12381G1 or KeyType.Bls12381G2 => VerifyBls(keyType, publicKey, data, signature),
            _ => throw new ArgumentException($"Unsupported key type for verification: {keyType}")
        };
    }

    private static DSASignatureFormat ToDsaFormat(EcdsaSignatureFormat format) => format switch
    {
        EcdsaSignatureFormat.Der => DSASignatureFormat.Rfc3279DerSequence,
        EcdsaSignatureFormat.IeeeP1363 => DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
        _ => throw new ArgumentException($"Unknown ECDSA signature format: {format}", nameof(format))
    };

    public byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        var algorithm = NSec.Cryptography.KeyAgreementAlgorithm.X25519;

        using var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey);
        var pubKey = NSec.Cryptography.PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey);

        using var sharedSecret = algorithm.Agree(key, pubKey)
            ?? throw new CryptographicException("X25519 key agreement failed.");

        // Extract the raw shared secret - use a key derivation to get usable bytes
        var kdf = KeyDerivationAlgorithm.HkdfSha256;
        using var derivedKey = kdf.DeriveKey(sharedSecret, ReadOnlySpan<byte>.Empty,
            ReadOnlySpan<byte>.Empty, AeadAlgorithm.ChaCha20Poly1305,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        return derivedKey.Export(KeyBlobFormat.RawSymmetricKey);
    }

    public byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        return keyType switch
        {
            KeyType.X25519 => DeriveX25519SharedSecret(privateKey, publicKey),
            KeyType.P256 => DeriveNistSharedSecret(privateKey, publicKey, ECCurve.NamedCurves.nistP256),
            KeyType.P384 => DeriveNistSharedSecret(privateKey, publicKey, ECCurve.NamedCurves.nistP384),
            KeyType.P521 => DeriveNistSharedSecret(privateKey, publicKey, ECCurve.NamedCurves.nistP521),
            _ => throw new ArgumentException($"Key type {keyType} is not ECDH-capable. Supported: X25519, P-256, P-384, P-521.", nameof(keyType))
        };
    }

    private static byte[] DeriveX25519SharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        var algorithm = NSec.Cryptography.KeyAgreementAlgorithm.X25519;

        using var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey);
        var pubKey = NSec.Cryptography.PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey);

        using var sharedSecret = algorithm.Agree(key, pubKey,
            new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport })
            ?? throw new CryptographicException("X25519 key agreement failed.");

        return sharedSecret.Export(SharedSecretBlobFormat.RawSharedSecret);
    }

    private static byte[] DeriveNistSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey, ECCurve curve)
    {
        using var localEcdh = ECDiffieHellman.Create();
        localEcdh.ImportParameters(ImportEcPrivateKey(privateKey, curve));

        using var remoteEcdh = ECDiffieHellman.Create();
        remoteEcdh.ImportParameters(ImportEcPublicKey(publicKey, curve));

        return localEcdh.DeriveRawSecretAgreement(remoteEcdh.PublicKey);
    }

    // --- Ed25519 (NSec.Cryptography) ---

    private static byte[] SignEd25519(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        var algorithm = SignatureAlgorithm.Ed25519;

        // Our private key is 32-byte seed. NSec's RawPrivateKey expects the seed.
        using var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return algorithm.Sign(key, data);
    }

    private static bool VerifyEd25519(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        var algorithm = SignatureAlgorithm.Ed25519;
        var pubKey = NSec.Cryptography.PublicKey.Import(algorithm, publicKey, KeyBlobFormat.RawPublicKey);
        return algorithm.Verify(pubKey, data, signature);
    }

    // --- P-256 / P-384 (System.Security.Cryptography.ECDsa) ---

    private static byte[] SignEcDsa(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data,
        ECCurve curve, HashAlgorithmName hashAlgorithm, DSASignatureFormat format)
    {
        using var ecdsa = ECDsa.Create();
        var parameters = ImportEcPrivateKey(privateKey, curve);
        ecdsa.ImportParameters(parameters);
        return ecdsa.SignData(data, hashAlgorithm, format);
    }

    private static bool VerifyEcDsa(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature, ECCurve curve, HashAlgorithmName hashAlgorithm, DSASignatureFormat format)
    {
        using var ecdsa = ECDsa.Create();
        var parameters = ImportEcPublicKey(publicKey, curve);
        ecdsa.ImportParameters(parameters);

        // P1363 is fixed-width (R‖S, each padded to the field byte length), so a signature of the
        // wrong length is definitively malformed. Reject it explicitly rather than depending on
        // backend exception semantics (Windows CNG throws, OpenSSL returns false).
        if (format == DSASignatureFormat.IeeeP1363FixedFieldConcatenation
            && signature.Length != 2 * ((ecdsa.KeySize + 7) / 8))
        {
            return false;
        }

        try
        {
            return ecdsa.VerifyData(data, signature, hashAlgorithm, format);
        }
        catch (CryptographicException)
        {
            // A malformed signature is a verification failure, not an exception (JOSE convention —
            // JWS verifiers expect false). Still needed for DER: Windows CNG throws on malformed
            // ASN.1 where OpenSSL returns false. Catching normalizes both platforms to false.
            return false;
        }
    }

    internal static ECParameters ImportEcPrivateKey(ReadOnlySpan<byte> privateKey, ECCurve curve)
    {
        return new ECParameters
        {
            Curve = curve,
            D = privateKey.ToArray()
        };
    }

    internal static ECParameters ImportEcPublicKey(ReadOnlySpan<byte> publicKey, ECCurve curve)
    {
        if (publicKey.Length > 0 && (publicKey[0] == 0x02 || publicKey[0] == 0x03))
        {
            // Compressed SEC1 point — decompress via SubjectPublicKeyInfo import
            return DecompressEcPoint(publicKey, curve);
        }

        if (publicKey.Length > 0 && publicKey[0] == 0x04)
        {
            // Uncompressed: 0x04 || x || y
            var coordLen = (publicKey.Length - 1) / 2;
            var x = publicKey.Slice(1, coordLen).ToArray();
            var y = publicKey.Slice(1 + coordLen, coordLen).ToArray();

            // Defense against the invalid-curve attack: reject off-curve (x, y) before
            // exposing them to ECDH / ECDSA via ECParameters.
            EcPointValidator.EnsureOnNistCurve(curve, x, y);

            return new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = x, Y = y }
            };
        }

        throw new ArgumentException("Invalid EC public key format. Expected compressed (0x02/0x03) or uncompressed (0x04) SEC1 point.");
    }

    // NIST P-256 curve parameters for point decompression
    private static readonly BigInteger P256Prime = BigInteger.Parse("0FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", NumberStyles.HexNumber);
    private static readonly BigInteger P256B = BigInteger.Parse("05AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", NumberStyles.HexNumber);

    // NIST P-384 curve parameters for point decompression
    private static readonly BigInteger P384Prime = BigInteger.Parse("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", NumberStyles.HexNumber);
    private static readonly BigInteger P384B = BigInteger.Parse("0B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", NumberStyles.HexNumber);

    // NIST P-521 curve parameters for point decompression.
    // p = 2^521 − 1 (a Mersenne prime, p ≡ 3 mod 4 so the standard sqrt path works).
    private static readonly BigInteger P521Prime = (BigInteger.One << 521) - 1;
    private static readonly BigInteger P521B = BigInteger.Parse(
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        NumberStyles.HexNumber);

    /// <summary>
    /// Decompress a compressed SEC1 EC point using the curve equation y² = x³ - 3x + b (mod p).
    /// Works for NIST P-256, P-384, and P-521 (all have p ≡ 3 mod 4).
    /// </summary>
    internal static ECParameters DecompressEcPoint(ReadOnlySpan<byte> compressedPoint, ECCurve curve)
    {
        var prefix = compressedPoint[0];
        var coordLen = compressedPoint.Length - 1;
        var xBytes = compressedPoint[1..].ToArray();

        var (p, b) = GetCurveParams(curve);
        var a = p - 3; // a = -3 for both P-256 and P-384

        var x = new BigInteger(xBytes, isUnsigned: true, isBigEndian: true);

        // y² = x³ + ax + b (mod p)
        var x3 = BigInteger.ModPow(x, 3, p);
        var rhs = (x3 + (a * x) % p + b) % p;

        // y = rhs^((p+1)/4) mod p (valid since p ≡ 3 mod 4)
        var y = BigInteger.ModPow(rhs, (p + 1) / 4, p);

        // 0x02 = even y, 0x03 = odd y
        if ((prefix == 0x02) != y.IsEven)
            y = p - y;

        var yBytes = y.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (yBytes.Length < coordLen)
        {
            var padded = new byte[coordLen];
            yBytes.CopyTo(padded, coordLen - yBytes.Length);
            yBytes = padded;
        }

        // Defense-in-depth: even after our own modular sqrt, validate the resulting point
        // satisfies the curve equation (reusing the rhs we just computed). A bug in BigInteger /
        // curve params would otherwise silently produce an off-curve key that imports without error.
        EcPointValidator.EnsureMatchesRhs(x, y, rhs, p);

        return new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = xBytes, Y = yBytes }
        };
    }

    /// <summary>
    /// Decompress a secp256k1 compressed point using NBitcoin and return (X, Y) coordinates.
    /// </summary>
    internal static (byte[] X, byte[] Y) DecompressSecp256k1Point(ReadOnlySpan<byte> compressedPoint)
    {
        if (!ECPubKey.TryCreate(compressedPoint, null, out _, out var pubKey))
            throw new ArgumentException("Invalid secp256k1 compressed point.");
        var uncompressed = new byte[65];
        pubKey.WriteToSpan(compressed: false, uncompressed, out _);
        return (uncompressed[1..33], uncompressed[33..65]);
    }

    internal static (BigInteger p, BigInteger b) GetCurveParams(ECCurve curve)
    {
        var oidValue = curve.Oid?.Value;
        if (oidValue == "1.2.840.10045.3.1.7") return (P256Prime, P256B);
        if (oidValue == "1.3.132.0.34") return (P384Prime, P384B);
        if (oidValue == "1.3.132.0.35") return (P521Prime, P521B);
        throw new ArgumentException("Unsupported curve for EC point decompression.");
    }

    // --- secp256k1 (NBitcoin.Secp256k1) ---

    private static byte[] SignSecp256k1(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        var privKey = ECPrivKey.Create(privateKey);

        // secp256k1 ECDSA expects a 32-byte message hash
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);

        var sig = privKey.SignECDSARFC6979(hash);

        Span<byte> compact = stackalloc byte[64];
        sig.WriteCompactToSpan(compact);
        return compact.ToArray();
    }

    private static bool VerifySecp256k1(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (!ECPubKey.TryCreate(publicKey, null, out _, out var pubKey))
            return false;

        if (!SecpECDSASignature.TryCreateFromCompact(signature, out var sig))
            return false;

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);

        return pubKey.SigVerify(sig, hash);
    }

    // --- BLS12-381 (Nethermind.Crypto.Bls) ---

    // BLS DSTs per ciphersuite (draft-irtf-cfrg-bls-signatures).
    // The G_ suffix in the DST name indicates which group the hash-to-curve targets:
    //   G2 DST → hash-to-G2 → sig in G2 (96 bytes), pubkey in G1 (48 bytes) → KeyType.Bls12381G1
    //   G1 DST → hash-to-G1 → sig in G1 (48 bytes), pubkey in G2 (96 bytes) → KeyType.Bls12381G2
    private static readonly byte[] BlsDstG2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"u8.ToArray();
    private static readonly byte[] BlsDstG1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"u8.ToArray();

    private static byte[] SignBls(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        var sk = new Bls.SecretKey();
        sk.FromBendian(privateKey);

        if (keyType == KeyType.Bls12381G1)
        {
            // G1 public key variant: signature lives in G2 → use G2 DST
            var msgPoint = new Bls.P2();
            msgPoint.HashTo(data, BlsDstG2, ReadOnlySpan<byte>.Empty);
            var sig = msgPoint.SignWith(sk);
            return sig.Compress();
        }
        else
        {
            // G2 public key variant: signature lives in G1 → use G1 DST
            var msgPoint = new Bls.P1();
            msgPoint.HashTo(data, BlsDstG1, ReadOnlySpan<byte>.Empty);
            var sig = msgPoint.SignWith(sk);
            return sig.Compress();
        }
    }

    private static bool VerifyBls(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        try
        {
            if (keyType == KeyType.Bls12381G1)
            {
                // G1 public key, G2 signature → G2 DST
                var pk = new Bls.P1Affine();
                pk.Decode(publicKey);
                var sig = new Bls.P2Affine();
                sig.Decode(signature);

                if (!pk.InGroup() || !sig.InGroup())
                    return false;

                var pairing = new Bls.Pairing(true, BlsDstG2);
                var err = pairing.Aggregate(pk, sig, data, ReadOnlySpan<byte>.Empty);
                if (err != Bls.ERROR.SUCCESS)
                    return false;

                pairing.Commit();
                return pairing.FinalVerify(default);
            }
            else
            {
                // G2 public key, G1 signature → G1 DST
                var pk = new Bls.P2Affine();
                pk.Decode(publicKey);
                var sig = new Bls.P1Affine();
                sig.Decode(signature);

                if (!pk.InGroup() || !sig.InGroup())
                    return false;

                var pairing = new Bls.Pairing(true, BlsDstG1);
                var err = pairing.Aggregate(pk, sig, data, ReadOnlySpan<byte>.Empty);
                if (err != Bls.ERROR.SUCCESS)
                    return false;

                pairing.Commit();
                return pairing.FinalVerify(default);
            }
        }
        catch (Bls.BlsException)
        {
            return false;
        }
    }
}
