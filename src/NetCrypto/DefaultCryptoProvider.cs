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
    /// <inheritdoc />
    public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
        => Sign(keyType, privateKey, data, EcdsaSignatureFormat.Der);

    /// <inheritdoc />
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

    /// <inheritdoc />
    public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        => Verify(keyType, publicKey, data, signature, EcdsaSignatureFormat.Der);

    /// <inheritdoc />
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

    /// <inheritdoc />
    public byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        // Validate both raw blobs before NSec (which throws FormatException on a wrong-length
        // import) so a malformed input surfaces as a parameter-named ArgumentException (NFR-3).
        RawKeyGuard.RequireLength(privateKey, 32, nameof(privateKey), "X25519 private key");
        RawKeyGuard.RequireLength(publicKey, 32, nameof(publicKey), "X25519 public key");

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

    /// <inheritdoc />
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
        RawKeyGuard.RequireLength(privateKey, 32, nameof(privateKey), "X25519 private key");
        RawKeyGuard.RequireLength(publicKey, 32, nameof(publicKey), "X25519 public key");

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
        var parameters = ImportEcPrivateKey(privateKey, curve);
        try
        {
            localEcdh.ImportParameters(parameters);
        }
        finally
        {
            // The platform key object now holds the scalar; wipe our managed copy of D.
            CryptographicOperations.ZeroMemory(parameters.D);
        }

        using var remoteEcdh = ECDiffieHellman.Create();
        remoteEcdh.ImportParameters(ImportEcPublicKey(publicKey, curve));

        return localEcdh.DeriveRawSecretAgreement(remoteEcdh.PublicKey);
    }

    // --- Ed25519 (NSec.Cryptography) ---

    private static byte[] SignEd25519(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
    {
        // Validate before NSec, whose Key.Import throws a raw FormatException on a wrong-length
        // raw blob; surface a parameter-named ArgumentException instead (NFR-3).
        RawKeyGuard.RequireLength(privateKey, 32, nameof(privateKey), "Ed25519 private key");

        var algorithm = SignatureAlgorithm.Ed25519;

        // Our private key is 32-byte seed. NSec's RawPrivateKey expects the seed.
        using var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return algorithm.Sign(key, data);
    }

    private static bool VerifyEd25519(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        // A wrong-length public key is a malformed caller input, not a verification outcome —
        // throw ArgumentException rather than leaking NSec's FormatException (matches the EC
        // verify path, which rejects wrong-length/malformed-format keys the same way). An
        // attacker-controlled wrong-length *signature* is handled by NSec.Verify returning false.
        RawKeyGuard.RequireLength(publicKey, 32, nameof(publicKey), "Ed25519 public key");

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
        try
        {
            ecdsa.ImportParameters(parameters);
        }
        finally
        {
            // The platform key object now holds the scalar; wipe our managed copy of D.
            CryptographicOperations.ZeroMemory(parameters.D);
        }
        return ecdsa.SignData(data, hashAlgorithm, format);
    }

    private static bool VerifyEcDsa(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature, ECCurve curve, HashAlgorithmName hashAlgorithm, DSASignatureFormat format)
    {
        using var ecdsa = ECDsa.Create();

        try
        {
            // Import inside the try: an off-curve / out-of-range public key makes EcPointValidator
            // throw CryptographicException, and an attacker-supplied key must surface as a
            // verification failure (false), not a thrown exception, in a JWS/verify loop. (A
            // wrong-length or malformed-format key still throws ArgumentException from
            // ImportEcPublicKey — that is a caller bug per NFR-3, not a verification outcome.)
            ecdsa.ImportParameters(ImportEcPublicKey(publicKey, curve));

            // P1363 is fixed-width (R‖S, each padded to the field byte length), so a signature of
            // the wrong length is definitively malformed. Reject it explicitly rather than
            // depending on backend exception semantics (Windows CNG throws, OpenSSL returns false).
            if (format == DSASignatureFormat.IeeeP1363FixedFieldConcatenation
                && signature.Length != 2 * ((ecdsa.KeySize + 7) / 8))
            {
                return false;
            }

            return ecdsa.VerifyData(data, signature, hashAlgorithm, format);
        }
        catch (CryptographicException)
        {
            // A malformed signature or off-curve key is a verification failure, not an exception
            // (JOSE convention — JWS verifiers expect false). Still needed for DER: Windows CNG
            // throws on malformed ASN.1 where OpenSSL returns false. Catching normalizes both
            // platforms — and the off-curve-key path — to false.
            return false;
        }
    }

    internal static ECParameters ImportEcPrivateKey(ReadOnlySpan<byte> privateKey, ECCurve curve)
    {
        // Validate the scalar length up front: a wrong-length D otherwise fails inside
        // ECDsa/ECDiffieHellman.ImportParameters with an opaque, platform-specific
        // CryptographicException (e.g. macOS AppleCommonCryptoCryptographicException). A
        // parameter-named ArgumentException makes the caller bug unambiguous (NFR-3).
        RawKeyGuard.RequireLength(privateKey, EcScalarByteLength(curve), nameof(privateKey), "EC private key");

        // Reject an out-of-range scalar up front. A correctly-sized D that is 0 or >= the curve
        // order n is not a valid private key; without this it would fail at ImportParameters time
        // with the same opaque platform CryptographicException. Normalizing it to a
        // parameter-named ArgumentException matches the BLS/secp256k1 paths (NFR-3 consistency).
        // Compared as fixed-length big-endian bytes rather than through BigInteger, which would
        // put an unwipeable copy of the private scalar on the managed heap (issue #17).
        if (!IsScalarInRange(privateKey, EcCurveOrderBytes(curve)))
            throw new ArgumentException(
                "EC private key scalar is out of range (must satisfy 0 < D < n).", nameof(privateKey));

        return new ECParameters
        {
            Curve = curve,
            D = privateKey.ToArray()
        };
    }

    // Constant-time 0 < d < n over same-length big-endian buffers (the length guard above
    // guarantees d.Length == n.Length). A short-circuiting compare (SequenceCompareTo /
    // IndexOfAnyExcept) would leak, via timing, how long a prefix of the secret scalar matches
    // the public order; this instead runs a full-width borrow-propagating subtract d − n (a
    // borrow left at the end ⇔ d < n) and OR-accumulates d's bytes (d ≠ 0), with no
    // data-dependent branches or early exits.
    private static bool IsScalarInRange(ReadOnlySpan<byte> d, ReadOnlySpan<byte> n)
    {
        var borrow = 0;
        var nonZero = 0;
        for (var i = d.Length - 1; i >= 0; i--)
        {
            var diff = d[i] - n[i] - borrow;
            borrow = (diff >> 8) & 1; // arithmetic shift: 1 exactly when the byte subtraction went negative
            nonZero |= d[i];
        }
        return (borrow == 1) & (nonZero != 0);
    }

    // NIST EC private-key scalar length (field byte length) for the supported curves.
    private static int EcScalarByteLength(ECCurve curve) => curve.Oid?.Value switch
    {
        "1.2.840.10045.3.1.7" => 32, // P-256
        "1.3.132.0.34" => 48,        // P-384
        "1.3.132.0.35" => 66,        // P-521 (521 bits → 66 bytes)
        _ => throw new ArgumentException("Unsupported curve for EC private key import.", nameof(curve))
    };

    // NIST curve group orders n (verified against the published FIPS 186-4 / SEC 2 values),
    // stored as fixed-length big-endian bytes matching each curve's scalar length so a candidate
    // D can be range-checked with a span compare instead of a heap-resident BigInteger.
    private static readonly byte[] P256OrderBytes = Convert.FromHexString(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    private static readonly byte[] P384OrderBytes = Convert.FromHexString(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");
    private static readonly byte[] P521OrderBytes = Convert.FromHexString(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409");

    // NIST EC private-key scalar upper bound (the curve order n) for the supported curves.
    private static byte[] EcCurveOrderBytes(ECCurve curve) => curve.Oid?.Value switch
    {
        "1.2.840.10045.3.1.7" => P256OrderBytes,
        "1.3.132.0.34" => P384OrderBytes,
        "1.3.132.0.35" => P521OrderBytes,
        _ => throw new ArgumentException("Unsupported curve for EC private key import.", nameof(curve))
    };

    internal static ECParameters ImportEcPublicKey(ReadOnlySpan<byte> publicKey, ECCurve curve)
    {
        // Validate the encoded length against THIS curve up front. Without it, a wrong-length body
        // either fails deep inside decompression / ImportParameters as an opaque, platform-specific
        // CryptographicException, or — for an in-range short coordinate — is silently accepted as a
        // different point. Both violate NFR-3: a wrong-length caller input is a caller bug and must
        // surface as a parameter-named ArgumentException (lesson L5), mirroring the private-key
        // RawKeyGuard on the signing side. Off-curve / out-of-range points of the CORRECT length are
        // still a CryptographicException (a genuine point-validity failure), thrown below.
        var coordLen = EcCoordinateByteLength(curve);

        if (publicKey.Length > 0 && (publicKey[0] == 0x02 || publicKey[0] == 0x03))
        {
            // Compressed SEC1 point: 0x02/0x03 || X.
            if (publicKey.Length != 1 + coordLen)
                throw new ArgumentException(
                    $"Compressed EC public key must be {1 + coordLen} bytes for this curve, got {publicKey.Length}.",
                    nameof(publicKey));
            return DecompressEcPoint(publicKey, curve);
        }

        if (publicKey.Length > 0 && publicKey[0] == 0x04)
        {
            // Uncompressed: 0x04 || x || y.
            if (publicKey.Length != 1 + 2 * coordLen)
                throw new ArgumentException(
                    $"Uncompressed EC public key must be {1 + 2 * coordLen} bytes for this curve, got {publicKey.Length}.",
                    nameof(publicKey));
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

        throw new ArgumentException(
            "Invalid EC public key format. Expected compressed (0x02/0x03) or uncompressed (0x04) SEC1 point.",
            nameof(publicKey));
    }

    // Byte length of one big-endian coordinate for an EC curve (P-256 = 32, P-384 = 48, P-521 = 66),
    // derived from the curve prime so a single GetCurveParams entry drives both validation and decode.
    private static int EcCoordinateByteLength(ECCurve curve)
    {
        var (p, _) = GetCurveParams(curve);
        return (int)((p.GetBitLength() + 7) / 8);
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
        // Validate length before handing to NBitcoin, whose ctor indexes a 32-byte span
        // and would otherwise throw IndexOutOfRangeException on bad input (NFR-3).
        if (privateKey.Length != 32)
            throw new ArgumentException("secp256k1 private key must be 32 bytes.", nameof(privateKey));
        if (!ECPrivKey.TryCreate(privateKey, out var privKey) || privKey is null)
            throw new ArgumentException("Invalid secp256k1 private key.", nameof(privateKey));

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
        // Nethermind's SecretKey.FromBendian throws BlsException on a wrong-length or otherwise
        // invalid (zero / out-of-range) scalar; convert both to a parameter-named
        // ArgumentException so bad input never leaks a backend exception type (NFR-3).
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
