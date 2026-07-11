using System.Collections.Concurrent;

namespace NetCrypto;

/// <summary>
/// Dictionary-backed key store for unit tests and development. NOT for production use.
/// </summary>
/// <remarks>
/// The store owns the private key material it holds: <see cref="DeleteAsync"/> zeroizes the
/// evicted key pair (delete destroys the key, it does not merely unlist it) and
/// <see cref="Dispose"/> zeroizes every remaining pair. Consequently a <see cref="KeyPair"/>
/// handed to <see cref="ImportAsync"/> is owned by the store from that point on — do not keep
/// using it independently, and do not import the same instance under two aliases. Deleting or
/// disposing concurrently with an in-flight operation on the same alias is a race the caller
/// must avoid.
/// </remarks>
public sealed class InMemoryKeyStore : IKeyStore, IDisposable
{
    private readonly ConcurrentDictionary<string, (KeyPair KeyPair, StoredKeyInfo Info)> _keys = new();
    private readonly IKeyGenerator _keyGenerator;
    private readonly ICryptoProvider _cryptoProvider;
    private volatile bool _disposed;

    /// <summary>Creates an in-memory key store backed by the given key generator and crypto provider.</summary>
    public InMemoryKeyStore(IKeyGenerator keyGenerator, ICryptoProvider cryptoProvider)
    {
        _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
    }

    /// <inheritdoc />
    public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var keyPair = _keyGenerator.Generate(keyType);
        var info = new StoredKeyInfo
        {
            Alias = alias,
            KeyType = keyType,
            PublicKey = keyPair.PublicKey
        };

        if (!_keys.TryAdd(alias, (keyPair, info)))
        {
            // The freshly generated pair never escaped — destroy it rather than orphan it.
            keyPair.Dispose();
            throw new InvalidOperationException($"Key alias '{alias}' already exists.");
        }

        return Task.FromResult(info);
    }

    /// <inheritdoc />
    public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        ArgumentNullException.ThrowIfNull(keyPair);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var info = new StoredKeyInfo
        {
            Alias = alias,
            KeyType = keyPair.KeyType,
            PublicKey = keyPair.PublicKey
        };

        if (!_keys.TryAdd(alias, (keyPair, info)))
            throw new InvalidOperationException($"Key alias '{alias}' already exists.");

        return Task.FromResult(info);
    }

    /// <inheritdoc />
    public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_keys.TryGetValue(alias, out var entry))
            return Task.FromResult<StoredKeyInfo?>(entry.Info);

        return Task.FromResult<StoredKeyInfo?>(null);
    }

    /// <inheritdoc />
    public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_keys.TryGetValue(alias, out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        // Borrow instead of reading KeyPair.PrivateKey: the clone-per-read getter would leave one
        // unzeroed private-key copy on the heap per signature.
        var signature = entry.KeyPair.WithPrivateKey(
            privateKey => _cryptoProvider.Sign(entry.KeyPair.KeyType, privateKey, data.Span));
        return Task.FromResult(signature);
    }

    /// <inheritdoc />
    public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_keys.TryGetValue(alias, out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        ISigner signer = new KeyStoreSigner(this, alias, entry.Info.KeyType, entry.Info.PublicKey);
        return Task.FromResult(signer);
    }

    /// <inheritdoc />
    public Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_keys.TryGetValue(alias, out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        // The stored private scalar is read here but never returned: only the raw shared secret Z
        // leaves the store, mirroring SignAsync. A real HSM-backed store runs the agreement in-enclave.
        byte[] z;
        try
        {
            z = entry.KeyPair.WithPrivateKey(
                privateKey => _cryptoProvider.DeriveSharedSecret(entry.KeyPair.KeyType, privateKey, peerPublicKey.Span));
        }
        catch (ArgumentException ex) when (ex.ParamName == "publicKey")
        {
            // The provider validates the peer key under its own parameter name ("publicKey"). Re-surface
            // it under THIS method's parameter so the caller sees the argument it actually passed; the
            // provider's detailed message is preserved on the inner exception. (A non-ECDH stored key
            // throws with ParamName "keyType" and is intentionally left to propagate unchanged.)
            throw new ArgumentException(
                "The peer public key is invalid for the stored key's algorithm.", nameof(peerPublicKey), ex);
        }
        return Task.FromResult(z);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        IReadOnlyList<string> aliases = _keys.Keys.ToList();
        return Task.FromResult(aliases);
    }

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var removed = _keys.TryRemove(alias, out var entry);
        if (removed)
            entry.KeyPair.Dispose(); // delete destroys the key material, not just the directory entry
        return Task.FromResult(removed);
    }

    /// <summary>
    /// Zeroizes every stored key pair and marks the store disposed. Idempotent; subsequent
    /// operations throw <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        foreach (var alias in _keys.Keys)
        {
            if (_keys.TryRemove(alias, out var entry))
                entry.KeyPair.Dispose();
        }
    }
}
