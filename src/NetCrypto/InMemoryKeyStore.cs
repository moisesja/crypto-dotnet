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

    public InMemoryKeyStore(IKeyGenerator keyGenerator, ICryptoProvider cryptoProvider)
    {
        _keyGenerator = keyGenerator ?? throw new ArgumentNullException(nameof(keyGenerator));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
    }

    public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default)
    {
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

    public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
    {
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

    public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default)
    {
        if (_keys.TryGetValue(alias, out var entry))
            return Task.FromResult<StoredKeyInfo?>(entry.Info);

        return Task.FromResult<StoredKeyInfo?>(null);
    }

    public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        if (!_keys.TryGetValue(alias, out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        var signature = _cryptoProvider.Sign(entry.KeyPair.KeyType, entry.KeyPair.PrivateKey, data.Span);
        return Task.FromResult(signature);
    }

    public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
    {
        if (!_keys.TryGetValue(alias, out var entry))
            throw new KeyNotFoundException($"Key alias '{alias}' not found.");

        ISigner signer = new KeyStoreSigner(this, alias, entry.Info.KeyType, entry.Info.PublicKey);
        return Task.FromResult(signer);
    }

    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
    {
        IReadOnlyList<string> aliases = _keys.Keys.ToList();
        return Task.FromResult(aliases);
    }

    public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
    {
        var removed = _keys.TryRemove(alias, out _);
        return Task.FromResult(removed);
    }
}
