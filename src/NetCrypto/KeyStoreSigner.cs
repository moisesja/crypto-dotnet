using NetCid;

namespace NetCrypto;

/// <summary>
/// Wraps a key store alias for HSM/vault-backed signing (secure path).
/// The private key never leaves the store.
/// </summary>
public sealed class KeyStoreSigner : ISigner
{
    private readonly IKeyStore _store;
    private readonly string _alias;

    /// <summary>Creates a signer that delegates signing for <paramref name="alias"/> to the given key store.</summary>
    public KeyStoreSigner(IKeyStore store, string alias, KeyType keyType, byte[] publicKey)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _alias = alias ?? throw new ArgumentNullException(nameof(alias));
        KeyType = keyType;
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    /// <inheritdoc />
    public KeyType KeyType { get; }

    /// <inheritdoc />
    public ReadOnlyMemory<byte> PublicKey { get; }

    /// <inheritdoc />
    public string MultibasePublicKey =>
        Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), PublicKey.Span), MultibaseEncoding.Base58Btc);

    /// <inheritdoc />
    public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        => _store.SignAsync(_alias, data, ct);
}
