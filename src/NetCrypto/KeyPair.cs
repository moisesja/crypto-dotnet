using Microsoft.IdentityModel.Tokens;
using NetCid;

namespace NetCrypto;

public sealed class KeyPair
{
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }
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
