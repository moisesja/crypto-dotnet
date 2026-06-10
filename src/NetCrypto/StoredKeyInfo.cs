using NetCid;

namespace NetCrypto;

/// <summary>
/// Metadata about a stored key. Never contains private key material.
/// </summary>
public sealed record StoredKeyInfo
{
    /// <summary>The alias under which the key is stored.</summary>
    public required string Alias { get; init; }

    /// <summary>The type of the stored key.</summary>
    public required KeyType KeyType { get; init; }

    /// <summary>The raw public key bytes.</summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key.
    /// </summary>
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), PublicKey), MultibaseEncoding.Base58Btc);
}
