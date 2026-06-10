using Microsoft.Extensions.DependencyInjection;
using NetCrypto;

// ============================================================
// NetCrypto Samples — Dependency Injection
// ============================================================
//
// AddNetCrypto() wires the default providers into any standard
// Microsoft.Extensions.DependencyInjection container. Application
// code then depends only on the NetCrypto *interfaces* — never on
// a concrete backend — which is what makes the implementation
// swappable later without touching that code.

// Track overall success so the program can exit non-zero if any
// expectation fails (useful when running samples in CI).
var ok = true;
void Check(bool condition, string what)
{
    Console.WriteLine($"  [{(condition ? "ok" : "FAIL")}] {what}");
    if (!condition) ok = false;
}

// -------------------------------------------------------
// 1. AddNetCrypto() — one call registers the defaults
// -------------------------------------------------------
Console.WriteLine("=== 1. AddNetCrypto on a ServiceCollection ===");

// One call registers all three default providers as singletons:
// they are stateless and cheap, so a single shared instance is ideal.
var services = new ServiceCollection();
services.AddNetCrypto();
using var provider = services.BuildServiceProvider();

var crypto = provider.GetRequiredService<ICryptoProvider>();
var bbs = provider.GetRequiredService<IBbsCryptoProvider>();
var keyGen = provider.GetRequiredService<IKeyGenerator>();

Console.WriteLine($"  ICryptoProvider    -> {crypto.GetType().Name}");
Console.WriteLine($"  IBbsCryptoProvider -> {bbs.GetType().Name}");
Console.WriteLine($"  IKeyGenerator      -> {keyGen.GetType().Name}");

Check(crypto is DefaultCryptoProvider, "ICryptoProvider resolves to DefaultCryptoProvider");
Check(bbs is DefaultBbsCryptoProvider, "IBbsCryptoProvider resolves to DefaultBbsCryptoProvider");
Check(keyGen is DefaultKeyGenerator, "IKeyGenerator resolves to DefaultKeyGenerator");

// Singleton lifetime: asking again returns the very same instance,
// so resolving providers anywhere in the app is free after first use.
Check(ReferenceEquals(crypto, provider.GetRequiredService<ICryptoProvider>()),
    "singleton: second resolve returns the same instance");
Console.WriteLine();

// -------------------------------------------------------
// 2. Use the resolved services — interfaces only
// -------------------------------------------------------
Console.WriteLine("=== 2. Sign/verify through the resolved interfaces ===");

// This is exactly what consuming code (a DID library, a credential
// issuer, ...) does: take the interfaces via constructor injection
// and never name a concrete provider.
var key = keyGen.Generate(KeyType.Ed25519);
var message = "resolved from the container"u8.ToArray();
var signature = crypto.Sign(KeyType.Ed25519, key.PrivateKey, message);

Console.WriteLine($"  Generated {key.KeyType} key, signature: {signature.Length} bytes");
Check(crypto.Verify(KeyType.Ed25519, key.PublicKey, message, signature),
    "signature verifies via the injected ICryptoProvider");
Console.WriteLine();

// -------------------------------------------------------
// 3. Posture-1 swap seam — your registration wins
// -------------------------------------------------------
Console.WriteLine("=== 3. Posture-1 swap seam — overriding the default ===");

// AddNetCrypto registers everything with TryAddSingleton: it only
// fills in interfaces that are NOT already registered. So if you
// register your own ICryptoProvider BEFORE calling AddNetCrypto,
// the default silently steps aside — no NetCrypto change required.
//
// Why would you? Typical reasons:
//   - a FIPS-validated provider for regulated deployments,
//   - an HSM/KMS-backed provider where raw keys never enter memory,
//   - a decorator adding audit logging or metrics (shown here).
var custom = new ServiceCollection();
custom.AddSingleton<ICryptoProvider>(new AuditingCryptoProvider(new DefaultCryptoProvider()));
custom.AddNetCrypto(); // TryAdd sees ICryptoProvider taken; skips it
using var customProvider = custom.BuildServiceProvider();

var swapped = customProvider.GetRequiredService<ICryptoProvider>();
Console.WriteLine($"  ICryptoProvider    -> {swapped.GetType().Name} (your registration won)");
Check(swapped is AuditingCryptoProvider, "consumer registration replaced the default");

// TryAdd is per-interface: the other two still get NetCrypto defaults.
Console.WriteLine($"  IKeyGenerator      -> {customProvider.GetRequiredService<IKeyGenerator>().GetType().Name} (still the default)");
Check(customProvider.GetRequiredService<IKeyGenerator>() is DefaultKeyGenerator,
    "interfaces you did not override keep their defaults");

// Prove the decorator is really in the call path: sign + verify
// through the container, then read the decorator's call counter.
var auditedSig = swapped.Sign(KeyType.Ed25519, key.PrivateKey, message);
Check(swapped.Verify(KeyType.Ed25519, key.PublicKey, message, auditedSig),
    "swapped provider signs and verifies correctly");
Check(((AuditingCryptoProvider)swapped).Calls == 2,
    $"decorator observed both calls (count = {((AuditingCryptoProvider)swapped).Calls})");
Console.WriteLine();

// -------------------------------------------------------
// 4. IKeyStore is intentionally NOT registered
// -------------------------------------------------------
Console.WriteLine("=== 4. IKeyStore — bring your own ===");

// NetCrypto ships no default key store: where private keys live
// (HSM, cloud KMS, database, memory) is an application decision,
// and a silently-registered in-memory default would be a security
// trap. GetService<IKeyStore>() therefore returns null — register
// your own implementation next to AddNetCrypto when you need one.
var keyStore = provider.GetService<IKeyStore>();
Console.WriteLine($"  GetService<IKeyStore>() -> {(keyStore is null ? "null" : keyStore.GetType().Name)}");
Check(keyStore is null, "IKeyStore is not registered by AddNetCrypto");
Console.WriteLine();

Console.WriteLine(ok
    ? "Done! All dependency injection examples completed successfully."
    : "FAILED: one or more expectations did not hold (see [FAIL] lines above).");
return ok ? 0 : 1;

/// <summary>
/// Example consumer-supplied provider: a decorator that wraps the default
/// and counts calls. This is the Posture-1 seam in action — a FIPS-validated
/// or HSM-backed implementation plugs in exactly the same way, and code
/// resolving <see cref="ICryptoProvider"/> never notices the swap.
/// </summary>
sealed class AuditingCryptoProvider(ICryptoProvider inner) : ICryptoProvider
{
    /// <summary>How many operations passed through the decorator.</summary>
    public int Calls { get; private set; }

    public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
        { Calls++; return inner.Sign(keyType, privateKey, data); }

    public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        { Calls++; return inner.Verify(keyType, publicKey, data, signature); }

    public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, EcdsaSignatureFormat format)
        { Calls++; return inner.Sign(keyType, privateKey, data, format); }

    public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format)
        { Calls++; return inner.Verify(keyType, publicKey, data, signature, format); }

    public byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
        { Calls++; return inner.KeyAgreement(privateKey, publicKey); }

    public byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
        { Calls++; return inner.DeriveSharedSecret(keyType, privateKey, publicKey); }
}
