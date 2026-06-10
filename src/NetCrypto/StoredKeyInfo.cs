using NetCid;

namespace NetCrypto;

/// <summary>
/// Metadata about a stored key. Never contains private key material.
/// </summary>
public sealed record StoredKeyInfo
{
    public required string Alias { get; init; }
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key.
    /// </summary>
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), PublicKey), MultibaseEncoding.Base58Btc);
}
