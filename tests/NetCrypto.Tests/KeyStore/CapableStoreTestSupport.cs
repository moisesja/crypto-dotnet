namespace NetCrypto.Tests.KeyStore;

/// <summary>
/// Shared fixtures and test doubles for the <see cref="ICapableKeyStore"/> suite (issue #26).
/// </summary>
internal static class CapableStoreTestSupport
{
    internal static readonly DefaultKeyGenerator KeyGenerator = new();
    internal static readonly DefaultCryptoProvider CryptoProvider = new();
    internal static readonly DefaultBbsCryptoProvider BbsProvider = new();

    /// <summary>A store with its own backend, in the default namespace, without BBS.</summary>
    internal static CapableInMemoryKeyStore NewStore() => new(KeyGenerator, CryptoProvider);

    /// <summary>A store with its own backend, in the default namespace, with the real BBS provider.</summary>
    internal static CapableInMemoryKeyStore NewBbsStore() => new(KeyGenerator, CryptoProvider, BbsProvider);

    /// <summary>A store over a caller-supplied backend and namespace.</summary>
    internal static CapableInMemoryKeyStore NewStore(
        InMemoryKeyStoreBackend backend, string ns, ICryptoProvider? crypto = null, IBbsCryptoProvider? bbs = null) =>
        new(backend, new KeyStoreNamespaceId(ns), KeyGenerator, crypto ?? CryptoProvider, bbs);

    /// <summary>A fresh idempotency key.</summary>
    internal static KeyOperationId NewOperationId() => new(Guid.NewGuid().ToString("N"));

    /// <summary>Generates a key through the capable path and returns its alias and instance id.</summary>
    internal static async Task<(string Alias, KeyInstanceId InstanceId)> SeedAsync(
        this CapableInMemoryKeyStore store, string alias, KeyType keyType)
    {
        var result = await store.GenerateAsync(new KeyGenerateRequest(NewOperationId(), alias, keyType));
        return (alias, result.InstanceId);
    }
}

/// <summary>
/// An <see cref="ICryptoProvider"/> that counts calls and can be told to misbehave: the
/// injected provider is a trust boundary (the Posture-1 swap seam), so the store's handling of
/// a hostile one is part of its contract, not an implementation detail.
/// </summary>
internal sealed class HostileCryptoProvider : ICryptoProvider
{
    private readonly ICryptoProvider _inner = CapableStoreTestSupport.CryptoProvider;

    /// <summary>Thrown instead of signing, when set.</summary>
    internal Func<Exception>? SignThrows { get; set; }

    /// <summary>Returned instead of a real signature, when set.</summary>
    internal Func<byte[]>? SignReturns { get; set; }

    /// <summary>Thrown instead of agreeing, when set.</summary>
    internal Func<Exception>? AgreeThrows { get; set; }

    /// <summary>Returned instead of a real shared secret, when set.</summary>
    internal Func<byte[]>? AgreeReturns { get; set; }

    /// <summary>The last buffer this provider handed back, so a test can mutate it afterwards.</summary>
    internal byte[]? LastReturnedBuffer { get; private set; }

    internal int SignCalls { get; private set; }

    internal int AgreeCalls { get; private set; }

    public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
        => Sign(keyType, privateKey, data, EcdsaSignatureFormat.Der);

    public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, EcdsaSignatureFormat format)
    {
        SignCalls++;
        if (SignThrows is { } thrower)
            throw thrower();
        if (SignReturns is { } producer)
            return LastReturnedBuffer = producer();

        return LastReturnedBuffer = _inner.Sign(keyType, privateKey, data, format);
    }

    public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        => _inner.Verify(keyType, publicKey, data, signature);

    public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format)
        => _inner.Verify(keyType, publicKey, data, signature, format);

    public byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
        => _inner.KeyAgreement(privateKey, publicKey);

    public byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        AgreeCalls++;
        if (AgreeThrows is { } thrower)
            throw thrower();
        if (AgreeReturns is { } producer)
            return LastReturnedBuffer = producer();

        return LastReturnedBuffer = _inner.DeriveSharedSecret(keyType, privateKey, publicKey);
    }
}

/// <summary>An <see cref="IBbsCryptoProvider"/> that reports itself unavailable and never signs.</summary>
internal sealed class UnavailableBbsProvider : IBbsCryptoProvider
{
    public BbsCiphersuite Ciphersuite => BbsCiphersuite.Bls12381Sha256;

    public bool IsAvailable => false;

    public byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages, ReadOnlySpan<byte> header = default)
        => throw new BbsUnavailableException("unavailable");

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages, ReadOnlySpan<byte> header = default)
        => throw new BbsUnavailableException("unavailable");

    public byte[] DeriveProof(ReadOnlySpan<byte> publicKey, byte[] signature, IReadOnlyList<byte[]> messages,
        IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> presentationHeader, ReadOnlySpan<byte> header = default)
        => throw new BbsUnavailableException("unavailable");

    public bool VerifyProof(ReadOnlySpan<byte> publicKey, byte[] proof, IReadOnlyList<byte[]> revealedMessages,
        IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> presentationHeader, ReadOnlySpan<byte> header = default)
        => throw new BbsUnavailableException("unavailable");
}
