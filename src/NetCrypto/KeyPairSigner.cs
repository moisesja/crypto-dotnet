namespace NetCrypto;

/// <summary>
/// Wraps a raw <see cref="KeyPair"/> for in-memory signing (simple path).
/// </summary>
/// <remarks>
/// By default the signer <b>owns</b> the wrapped key pair: <see cref="Dispose"/> disposes it,
/// zeroizing the private key material. Pass <c>ownsKeyPair: false</c> to the three-argument
/// constructor when the key pair's lifecycle is managed elsewhere. Callers that never dispose
/// keep the pre-1.2.0 behavior unchanged.
/// </remarks>
public sealed class KeyPairSigner : ISigner, IDisposable
{
    private readonly KeyPair _keyPair;
    private readonly ICryptoProvider _crypto;
    private readonly bool _ownsKeyPair;
    private volatile bool _disposed;

    /// <summary>
    /// Creates a signer that signs with the given key pair using the given crypto provider.
    /// The signer takes ownership of <paramref name="keyPair"/>: disposing the signer disposes
    /// (zeroizes) the key pair.
    /// </summary>
    public KeyPairSigner(KeyPair keyPair, ICryptoProvider crypto)
        : this(keyPair, crypto, ownsKeyPair: true)
    {
    }

    /// <summary>
    /// Creates a signer that signs with the given key pair using the given crypto provider.
    /// </summary>
    /// <param name="keyPair">The key pair to sign with.</param>
    /// <param name="crypto">The crypto provider that performs the signing.</param>
    /// <param name="ownsKeyPair">When true (the two-argument constructor's default), disposing
    /// the signer disposes — zeroizes — <paramref name="keyPair"/>; when false the caller keeps
    /// ownership of the key pair's lifecycle.</param>
    public KeyPairSigner(KeyPair keyPair, ICryptoProvider crypto, bool ownsKeyPair)
    {
        _keyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
        _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
        _ownsKeyPair = ownsKeyPair;
    }

    /// <inheritdoc />
    public KeyType KeyType => _keyPair.KeyType;

    /// <inheritdoc />
    public ReadOnlyMemory<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _keyPair.PublicKey;
        }
    }

    /// <inheritdoc />
    public string MultibasePublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _keyPair.MultibasePublicKey;
        }
    }

    /// <inheritdoc />
    public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Borrow instead of reading KeyPair.PrivateKey: the clone-per-read getter would leave one
        // unzeroed private-key copy on the heap per signature.
        var sig = _keyPair.WithPrivateKey(privateKey => _crypto.Sign(_keyPair.KeyType, privateKey, data.Span));
        return Task.FromResult(sig);
    }

    /// <summary>
    /// Disposes the signer; when it owns the wrapped key pair (the default), the key pair is
    /// disposed too, zeroizing its private key material. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (_ownsKeyPair)
            _keyPair.Dispose();
    }
}
