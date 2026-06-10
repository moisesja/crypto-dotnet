namespace NetCrypto;

/// <summary>Supported cryptographic key types.</summary>
public enum KeyType
{
    /// <summary>Ed25519 signing key (EdDSA).</summary>
    Ed25519,

    /// <summary>X25519 key-agreement key (ECDH over Curve25519).</summary>
    X25519,

    /// <summary>NIST P-256 (secp256r1) key.</summary>
    P256,

    /// <summary>NIST P-384 (secp384r1) key.</summary>
    P384,

    /// <summary>secp256k1 key.</summary>
    Secp256k1,

    /// <summary>BLS12-381 key with the public key in the G1 group.</summary>
    Bls12381G1,

    /// <summary>BLS12-381 key with the public key in the G2 group.</summary>
    Bls12381G2,

    /// <summary>NIST P-521 (secp521r1) key.</summary>
    P521
}
