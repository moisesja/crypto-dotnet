using Microsoft.IdentityModel.Tokens;
using NetCid;

namespace NetCrypto;

/// <summary>A cryptographic key pair holding both public and private key material.</summary>
public sealed class KeyPair
{
    private readonly byte[] _publicKey = [];
    private readonly byte[] _privateKey = [];

    /// <summary>The type of the key pair.</summary>
    public required KeyType KeyType { get; init; }

    /// <summary>
    /// The raw public key bytes. Defensively copied on both set and get: mutating the returned
    /// array (or the array used to initialize the property) never alters this key pair.
    /// </summary>
    public required byte[] PublicKey
    {
        get => (byte[])_publicKey.Clone();
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            _publicKey = (byte[])value.Clone();
        }
    }

    /// <summary>
    /// The raw private key bytes. Defensively copied on both set and get: mutating the returned
    /// array (or the array used to initialize the property) never alters this key pair.
    /// </summary>
    public required byte[] PrivateKey
    {
        get => (byte[])_privateKey.Clone();
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            _privateKey = (byte[])value.Clone();
        }
    }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key (e.g., "z6Mkf...")
    /// </summary>
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), _publicKey), MultibaseEncoding.Base58Btc);

    /// <summary>JWK representation of the public key.</summary>
    public JsonWebKey ToPublicJwk() => JwkConverter.ToPublicJwk(this);

    /// <summary>JWK representation of the key pair (includes private key material).</summary>
    public JsonWebKey ToPrivateJwk() => JwkConverter.ToPrivateJwk(this);
}
