using NetCid;

namespace NetCrypto;

/// <summary>
/// A public-key-only reference (no private key material).
/// Returned by <see cref="IKeyGenerator.FromPublicKey"/>.
/// </summary>
public sealed class PublicKeyReference
{
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key.
    /// </summary>
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), PublicKey), MultibaseEncoding.Base58Btc);
}
