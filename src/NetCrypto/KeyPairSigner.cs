namespace NetCrypto;

/// <summary>
/// Wraps a raw <see cref="KeyPair"/> for in-memory signing (simple path).
/// </summary>
public sealed class KeyPairSigner : ISigner
{
    private readonly KeyPair _keyPair;
    private readonly ICryptoProvider _crypto;

    /// <summary>Creates a signer that signs with the given key pair using the given crypto provider.</summary>
    public KeyPairSigner(KeyPair keyPair, ICryptoProvider crypto)
    {
        _keyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
        _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
    }

    /// <inheritdoc />
    public KeyType KeyType => _keyPair.KeyType;

    /// <inheritdoc />
    public ReadOnlyMemory<byte> PublicKey => _keyPair.PublicKey;

    /// <inheritdoc />
    public string MultibasePublicKey => _keyPair.MultibasePublicKey;

    /// <inheritdoc />
    public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        var sig = _crypto.Sign(_keyPair.KeyType, _keyPair.PrivateKey, data.Span);
        return Task.FromResult(sig);
    }
}
