using NetCid;

namespace NetCrypto;

/// <summary>
/// A public-key-only reference (no private key material).
/// Returned by <see cref="IKeyGenerator.FromPublicKey"/>.
/// </summary>
public sealed class PublicKeyReference
{
    /// <summary>The type of the referenced key.</summary>
    public required KeyType KeyType { get; init; }

    /// <summary>The raw public key bytes.</summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key.
    /// </summary>
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), PublicKey), MultibaseEncoding.Base58Btc);
}
