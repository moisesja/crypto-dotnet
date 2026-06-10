namespace NetCrypto;

public interface IKeyGenerator
{
    /// <summary>Generate a new random key pair for the given key type.</summary>
    KeyPair Generate(KeyType keyType);

    /// <summary>Restore a key pair from an existing private key.</summary>
    KeyPair FromPrivateKey(KeyType keyType, ReadOnlySpan<byte> privateKey);

    /// <summary>Create a public-only key reference from a public key.</summary>
    PublicKeyReference FromPublicKey(KeyType keyType, ReadOnlySpan<byte> publicKey);

    /// <summary>Derive an X25519 key agreement key from an Ed25519 key pair.</summary>
    KeyPair DeriveX25519FromEd25519(KeyPair ed25519KeyPair);

    /// <summary>
    /// Derive an X25519 public key from an Ed25519 public key using the birational map.
    /// Used during did:key resolution when only the public key is available.
    /// </summary>
    PublicKeyReference DeriveX25519PublicKeyFromEd25519(ReadOnlySpan<byte> ed25519PublicKey);
}
