using Microsoft.IdentityModel.Tokens;
using NetCid;

namespace NetCrypto;

/// <summary>A cryptographic key pair holding both public and private key material.</summary>
public sealed class KeyPair
{
    /// <summary>The type of the key pair.</summary>
    public required KeyType KeyType { get; init; }

    /// <summary>The raw public key bytes.</summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>The raw private key bytes.</summary>
    public required byte[] PrivateKey { get; init; }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key (e.g., "z6Mkf...")
    /// </summary>
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), PublicKey), MultibaseEncoding.Base58Btc);

    /// <summary>JWK representation of the public key.</summary>
    public JsonWebKey ToPublicJwk() => JwkConverter.ToPublicJwk(this);

    /// <summary>JWK representation of the key pair (includes private key material).</summary>
    public JsonWebKey ToPrivateJwk() => JwkConverter.ToPrivateJwk(this);
}
