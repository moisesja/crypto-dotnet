using NetCid;

namespace NetCrypto;

/// <summary>
/// A public-key-only reference (no private key material).
/// Returned by <see cref="IKeyGenerator.FromPublicKey"/>.
/// </summary>
public sealed class PublicKeyReference
{
    private readonly byte[] _publicKey = [];

    /// <summary>The type of the referenced key.</summary>
    public required KeyType KeyType { get; init; }

    /// <summary>
    /// The raw public key bytes. Defensively copied on both set and get: mutating the returned
    /// array (or the array used to initialize the property) never alters this reference.
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
}
