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
    /// The immutable identity of this key instance, when the store that produced the info
    /// tracks one (see <see cref="ICapableKeyStore"/>).
    /// </summary>
    /// <remarks>
    /// Optional and <c>null</c> by default, so infos produced through the plain
    /// <see cref="IKeyStore"/> members — which have no instance concept — are unchanged. A
    /// capable store populates it, letting a caller hold on to the instance and detect later
    /// alias rebinding instead of silently signing under a different key.
    /// </remarks>
    public KeyInstanceId? InstanceId { get; init; }

    /// <summary>
    /// The multicodec-prefixed, multibase-encoded public key.
    /// </summary>
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), _publicKey), MultibaseEncoding.Base58Btc);

    /// <summary>
    /// Value equality over <see cref="Alias"/>, <see cref="KeyType"/>,
    /// <see cref="InstanceId"/>, and the <see cref="PublicKey"/> <i>content</i>. The
    /// record-synthesized comparison would compare the key array by reference, making
    /// value-identical infos unequal in sets and dictionaries.
    /// </summary>
    public bool Equals(StoredKeyInfo? other) =>
        other is not null
        && Alias == other.Alias
        && KeyType == other.KeyType
        && Nullable.Equals(InstanceId, other.InstanceId)
        && _publicKey.AsSpan().SequenceEqual(other._publicKey);

    /// <summary>Hash code consistent with the content-based <see cref="Equals(StoredKeyInfo)"/>.</summary>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Alias);
        hash.Add(KeyType);
        hash.Add(InstanceId);
        hash.AddBytes(_publicKey);
        return hash.ToHashCode();
    }
}
