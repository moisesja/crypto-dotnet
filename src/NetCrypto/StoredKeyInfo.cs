using NetCid;

namespace NetCrypto;

/// <summary>
/// Metadata about a stored key. Never contains private key material.
/// </summary>
public sealed record StoredKeyInfo
{
    private readonly byte[] _publicKey = [];

    /// <summary>The alias under which the key is stored.</summary>
    public required string Alias { get; init; }

    /// <summary>The type of the stored key.</summary>
    public required KeyType KeyType { get; init; }

    /// <summary>
    /// The raw public key bytes. Defensively copied on both set and get: mutating the returned
    /// array (or the array used to initialize the property) never alters this info.
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
    /// The multicodec-prefixed, multibase-encoded public key.
    /// </summary>
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), _publicKey), MultibaseEncoding.Base58Btc);

    /// <summary>
    /// Value equality over <see cref="Alias"/>, <see cref="KeyType"/>, and the
    /// <see cref="PublicKey"/> <i>content</i>. The record-synthesized comparison would compare
    /// the key array by reference, making value-identical infos unequal in sets and dictionaries.
    /// </summary>
    public bool Equals(StoredKeyInfo? other) =>
        other is not null
        && Alias == other.Alias
        && KeyType == other.KeyType
        && _publicKey.AsSpan().SequenceEqual(other._publicKey);

    /// <summary>Hash code consistent with the content-based <see cref="Equals(StoredKeyInfo)"/>.</summary>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Alias);
        hash.Add(KeyType);
        hash.AddBytes(_publicKey);
        return hash.ToHashCode();
    }
}
