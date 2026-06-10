using NetCrypto;

// ============================================================
// NetCrypto Samples — Signers
// ISigner, KeyPairSigner, IKeyStore, KeyStoreSigner, StoredKeyInfo
// ============================================================
//
// ISigner is the single signing abstraction the rest of the stack
// (DIDs, credentials, data proofs) is written against. Callers never
// touch private key bytes — they only ask "sign these bytes for me".
// That way the same calling code works whether the key sits in memory,
// in a vault, or inside an HSM that never releases it.

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();
var message = "hello from NetCrypto signers"u8.ToArray();

// -------------------------------------------------------
// 1. KeyPairSigner — the simple in-memory path
// -------------------------------------------------------
Console.WriteLine("=== 1. KeyPairSigner (raw key in memory) ===");

// When you already hold raw key material (ephemeral keys, dev setups),
// KeyPairSigner puts a KeyPair + ICryptoProvider behind the ISigner door.
var keyPair = keyGen.Generate(KeyType.Ed25519);
ISigner pairSigner = new KeyPairSigner(keyPair, crypto);

Console.WriteLine($"  KeyType:   {pairSigner.KeyType}");
// MultibasePublicKey is the multicodec-prefixed, base58btc encoding used
// by did:key and verification methods ("z6Mk..." marks Ed25519).
Console.WriteLine($"  Multibase: {pairSigner.MultibasePublicKey}");

var sig1 = await pairSigner.SignAsync(message);
// Verifying needs only the PUBLIC key, so it happens on the low-level
// ICryptoProvider — no ISigner (and no private key) required.
var ok1 = crypto.Verify(pairSigner.KeyType, pairSigner.PublicKey.Span, message, sig1);
Console.WriteLine($"  Signature: {sig1.Length} bytes, verifies: {ok1}");
Check(ok1, "KeyPairSigner signature verifies");
Console.WriteLine();

// -------------------------------------------------------
// 2. IKeyStore — private keys live BEHIND a wall
// -------------------------------------------------------
Console.WriteLine("=== 2. IKeyStore (minimal store defined in this file) ===");

// MiniKeyStore (bottom of this file) implements all seven IKeyStore
// members. Notice what the interface deliberately does NOT have: a
// "GetPrivateKey". Keys are born inside the store, and the only way to
// use one is SignAsync(alias, data) — the single signing door.
IKeyStore store = new MiniKeyStore(keyGen, crypto);

// GenerateAsync creates the key inside the store; the caller only ever
// receives StoredKeyInfo — alias, key type and public key. Nothing secret.
var info = await store.GenerateAsync("issuer-key", KeyType.Ed25519);
Console.WriteLine($"  Alias:     {info.Alias}");
Console.WriteLine($"  KeyType:   {info.KeyType}");
Console.WriteLine($"  Multibase: {info.MultibasePublicKey}");

// GetInfoAsync re-reads that public-only metadata (null if absent).
var fetched = await store.GetInfoAsync("issuer-key");
Check(fetched is not null && fetched.Alias == "issuer-key", "GetInfoAsync finds the stored key");

// SignAsync(alias, data): bytes in, signature out — the private key
// never crosses the call boundary. This is the whole HSM-first pattern.
var sig2 = await store.SignAsync("issuer-key", message);
var ok2 = crypto.Verify(info.KeyType, info.PublicKey, message, sig2);
Console.WriteLine($"  Store-signed: {sig2.Length} bytes, verifies: {ok2}");
Check(ok2, "key store signature verifies");
Console.WriteLine();

// -------------------------------------------------------
// 3. KeyStoreSigner — ISigner over a store alias
// -------------------------------------------------------
Console.WriteLine("=== 3. KeyStoreSigner via IKeyStore.CreateSignerAsync ===");

// CreateSignerAsync wraps an alias as an ISigner (a KeyStoreSigner), so
// code written against ISigner — a DID method, a proof generator — cannot
// tell, and must not care, whether a raw key or a vault is behind it.
var storeSigner = await store.CreateSignerAsync("issuer-key");
Console.WriteLine($"  Signer public key matches StoredKeyInfo: {storeSigner.MultibasePublicKey == info.MultibasePublicKey}");

// SignAsync here delegates straight back to store.SignAsync(alias, ...).
var sig3 = await storeSigner.SignAsync(message);
var ok3 = crypto.Verify(storeSigner.KeyType, storeSigner.PublicKey.Span, message, sig3);
Console.WriteLine($"  Signed via ISigner: verifies: {ok3}");
Check(storeSigner.MultibasePublicKey == info.MultibasePublicKey, "signer exposes the stored public key");
Check(ok3, "KeyStoreSigner signature verifies");
Console.WriteLine();

// -------------------------------------------------------
// 4. Import, list, delete — the housekeeping members
// -------------------------------------------------------
Console.WriteLine("=== 4. ImportAsync / ListAsync / DeleteAsync ===");

// ImportAsync is the migration path: a key generated elsewhere is handed
// over ONCE; from then on it is used only through the store's signing door.
var external = keyGen.Generate(KeyType.P256);
var imported = await store.ImportAsync("migrated-p256", external);
Console.WriteLine($"  Imported '{imported.Alias}' ({imported.KeyType})");

var aliases = await store.ListAsync();
Console.WriteLine($"  Aliases:   [{string.Join(", ", aliases)}]");
Check(aliases.Count == 2, "store lists both keys");

// DeleteAsync is how key rotation ends: the old key ceases to exist.
var deleted = await store.DeleteAsync("migrated-p256");
Console.WriteLine($"  Deleted 'migrated-p256': {deleted}");
Check(deleted && await store.GetInfoAsync("migrated-p256") is null, "deleted key is gone");
Console.WriteLine();

// -------------------------------------------------------
// 5. InMemoryKeyStore — the store NetCrypto ships
// -------------------------------------------------------
Console.WriteLine("=== 5. InMemoryKeyStore (ships with NetCrypto) ===");

// You do not have to write your own store for tests and development:
// NetCrypto ships InMemoryKeyStore with this exact contract. It keeps
// keys in a plain dictionary — convenient, but NOT for production.
// Production stores should sit on an HSM, OS keychain or vault.
IKeyStore devStore = new InMemoryKeyStore(keyGen, crypto);
await devStore.GenerateAsync("dev-key", KeyType.Secp256k1);
var devSigner = await devStore.CreateSignerAsync("dev-key");
var devSig = await devSigner.SignAsync(message);
var devOk = crypto.Verify(devSigner.KeyType, devSigner.PublicKey.Span, message, devSig);
Console.WriteLine($"  secp256k1 sign + verify through InMemoryKeyStore: {devOk}");
Check(devOk, "InMemoryKeyStore signature verifies");
Console.WriteLine();

Console.WriteLine("Done! All signer examples completed successfully.");
return 0;

// Prints and exits non-zero the moment an expectation fails, so CI (and
// you) can trust that a 0 exit code means every step above really worked.
static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}

// A minimal IKeyStore showing the full seven-member contract. A real
// implementation would keep the key inside an HSM/keychain/vault, but the
// shape stays the same: private keys go in, only signatures come out.
sealed class MiniKeyStore(IKeyGenerator keyGen, ICryptoProvider crypto) : IKeyStore
{
    // alias -> key material. Private field — never handed to callers.
    private readonly Dictionary<string, KeyPair> _keys = new();

    public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default)
        => ImportAsync(alias, keyGen.Generate(keyType), ct); // the key is born inside the store

    public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
    {
        _keys.Add(alias, keyPair);
        return Task.FromResult(Info(alias, keyPair)); // metadata only goes back out
    }

    public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default)
        => Task.FromResult<StoredKeyInfo?>(_keys.TryGetValue(alias, out var kp) ? Info(alias, kp) : null);

    // The single signing door: data in, signature out, key stays put.
    public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
        => Task.FromResult(crypto.Sign(_keys[alias].KeyType, _keys[alias].PrivateKey, data.Span));

    // KeyStoreSigner only needs public facts; its SignAsync calls back here.
    public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
        => Task.FromResult<ISigner>(new KeyStoreSigner(this, alias, _keys[alias].KeyType, _keys[alias].PublicKey));

    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<string>>(_keys.Keys.ToList());

    public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
        => Task.FromResult(_keys.Remove(alias));

    private static StoredKeyInfo Info(string alias, KeyPair kp)
        => new() { Alias = alias, KeyType = kp.KeyType, PublicKey = kp.PublicKey };
}
