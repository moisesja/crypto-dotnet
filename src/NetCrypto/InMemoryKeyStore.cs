using System.Collections.Concurrent;

namespace NetCrypto;

/// <summary>
/// Dictionary-backed key store for unit tests and development. NOT for production use.
/// </summary>
public sealed class InMemoryKeyStore : IKeyStore
{
    private readonly ConcurrentDictionary<string, (KeyPair KeyPair, StoredKeyInfo Info)> _keys = new();
    private readonly IKeyGenerator _keyGenerator;
    private readonly ICryptoProvider _cryptoProvider;

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

        var keyPair = _keyGenerator.Generate(keyType);
        var info = new StoredKeyInfo
        {
            Alias = alias,
            KeyType = keyType,
            PublicKey = keyPair.PublicKey
        };

        if (!_keys.TryAdd(alias, (keyPair, info)))
            throw new InvalidOperationException($"Key alias '{alias}' already exists.");

        return Task.FromResult(info);
    }

    /// <inheritdoc />
    public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);
        ArgumentNullException.ThrowIfNull(keyPair);

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

        if (_keys.TryGetValue(alias, out var entry))
            return Task.FromResult<StoredKeyInfo?>(entry.Info);

        return Task.FromResult<StoredKeyInfo?>(null);
    }

    /// <inheritdoc />
    public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);

        if (!_keys.TryGetValue(alias, out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        var signature = _cryptoProvider.Sign(entry.KeyPair.KeyType, entry.KeyPair.PrivateKey, data.Span);
        return Task.FromResult(signature);
    }

    /// <inheritdoc />
    public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);

        if (!_keys.TryGetValue(alias, out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        ISigner signer = new KeyStoreSigner(this, alias, entry.Info.KeyType, entry.Info.PublicKey);
        return Task.FromResult(signer);
    }

    /// <inheritdoc />
    public Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);

        if (!_keys.TryGetValue(alias, out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        // The stored private scalar is read here but never returned: only the raw shared secret Z
        // leaves the store, mirroring SignAsync. A real HSM-backed store runs the agreement in-enclave.
        var z = _cryptoProvider.DeriveSharedSecret(entry.KeyPair.KeyType, entry.KeyPair.PrivateKey, peerPublicKey.Span);
        return Task.FromResult(z);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
    {
        IReadOnlyList<string> aliases = _keys.Keys.ToList();
        return Task.FromResult(aliases);
    }

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(alias);

        var removed = _keys.TryRemove(alias, out _);
        return Task.FromResult(removed);
    }
}
