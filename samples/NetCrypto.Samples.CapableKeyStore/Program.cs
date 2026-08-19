using NetCrypto;

// ============================================================
// NetCrypto Samples — Capable key store (custody boundary)
// ICapableKeyStore, IKeyStoreCapabilityProvider, CapableInMemoryKeyStore,
// InMemoryKeyStoreBackend, KeyStoreCapabilitySet, KeyStoreCapability,
// KeyStoreOperation, KeyStoreAlgorithms, KeyStoreAlgorithmId,
// KeyStoreNamespaceId, KeyInstanceId, KeyOperationId, KeyMutationKind,
// KeyGenerateRequest, KeyImportRequest, KeyDeleteRequest, KeySignRequest,
// KeyBbsSignRequest, KeyAgreementRequest, KeyMutationResult, KeyDeleteResult,
// KeyMutationOutcome, KeyGeneratedOutcome, KeyImportedOutcome,
// KeyDeletionOutcome, TransferableKeyMaterial, KeyStoreException, KeyStoreError
// ============================================================
//
// IKeyStore says "sign with the key behind this alias". That is enough for an
// in-memory store and not enough for a custody backend — a cloud KMS, an HSM
// partition, an encrypted software keystore — where you additionally need to
// know what the backend can do before you use it, which tenant you are allowed
// to touch, which *key instance* an alias currently holds, how to retry a
// mutation that may or may not have been applied, and which encoding a
// signature comes back in.
//
// ICapableKeyStore adds exactly that, additively: IKeyStore itself gains no
// member, so every existing store and caller is untouched.

var keyGenerator = new DefaultKeyGenerator();
var cryptoProvider = new DefaultCryptoProvider();
var bbsProvider = new DefaultBbsCryptoProvider();

// One backend, two tenants. Sharing the backend is what makes namespace
// scoping meaningful — over two separate dictionaries it would prove nothing.
using var backend = new InMemoryKeyStoreBackend();
using var issuer = new CapableInMemoryKeyStore(
    backend, new KeyStoreNamespaceId("tenant/issuer"), keyGenerator, cryptoProvider, bbsProvider);
using var neighbour = new CapableInMemoryKeyStore(
    backend, new KeyStoreNamespaceId("tenant/neighbour"), keyGenerator, cryptoProvider, bbsProvider);

ICapableKeyStore store = issuer;
Console.WriteLine($"Namespace: {store.NamespaceId}");

// -------------------------------------------------------
// 1. Discover, then act — never probe by failing
// -------------------------------------------------------
Console.WriteLine("\n=== 1. Capability discovery ===");

// GetCapabilitiesAsync comes from IKeyStoreCapabilityProvider. It is
// side-effect-free, deeply immutable, and its Revision is stable for the
// lifetime of this store instance.
KeyStoreCapabilitySet capabilities = await store.GetCapabilitiesAsync();
Console.WriteLine($"  Revision:     {capabilities.Revision}");
Console.WriteLine($"  Capabilities: {capabilities.Capabilities.Count}");

foreach (KeyStoreOperation operation in Enum.GetValues<KeyStoreOperation>())
{
    var count = capabilities.Capabilities.Count(c => c.Operation == operation);
    Console.WriteLine($"    {operation,-13} {count}");
}

// Find() is the "validate, then act" half: no capability means the operation
// would be refused, so route the key elsewhere instead of failing a round-trip.
KeyStoreCapability? p256Signing =
    capabilities.Find(KeyType.P256, KeyStoreOperation.Sign, KeyStoreAlgorithms.Es256P1363);
Console.WriteLine($"  P-256 / es256-p1363 → " +
    $"{(p256Signing is null ? "not advertised" : $"max {p256Signing.MaxInputBytes} input bytes")}");

// Every algorithm identifier NetCrypto mints. The identifier binds the curve,
// the hash, AND the observable encoding — which is what makes the JOSE/X.509
// split reachable for a key that never leaves its store.
KeyStoreAlgorithmId[] signingAlgorithms =
[
    KeyStoreAlgorithms.Ed25519,
    KeyStoreAlgorithms.Es256Der, KeyStoreAlgorithms.Es256P1363,
    KeyStoreAlgorithms.Es384Der, KeyStoreAlgorithms.Es384P1363,
    KeyStoreAlgorithms.Es512Der, KeyStoreAlgorithms.Es512P1363,
    KeyStoreAlgorithms.Es256K,
    KeyStoreAlgorithms.Bls12381G1Basic, KeyStoreAlgorithms.Bls12381G2Basic,
];
KeyStoreAlgorithmId[] agreementAlgorithms =
[
    KeyStoreAlgorithms.EcdhX25519, KeyStoreAlgorithms.EcdhP256,
    KeyStoreAlgorithms.EcdhP384, KeyStoreAlgorithms.EcdhP521,
];
Console.WriteLine($"  Signing ids:   {string.Join(", ", signingAlgorithms.Select(a => a.Value))}");
Console.WriteLine($"  Agreement ids: {string.Join(", ", agreementAlgorithms.Select(a => a.Value))}");
Console.WriteLine($"  BBS id:        {KeyStoreAlgorithms.BbsBls12381Sha256.Value}");

// -------------------------------------------------------
// 2. Idempotent generate — a retry is not a second key
// -------------------------------------------------------
Console.WriteLine("\n=== 2. Idempotent mutation ===");

// The operation id is minted by the CALLER and reused across retries of that
// one logical operation. Mutation identity is (namespace, kind, operation id).
var signingOperation = new KeyOperationId(Guid.NewGuid().ToString("N"));
var generate = new KeyGenerateRequest(signingOperation, "signing-key", KeyType.P256);

KeyMutationResult created = await store.GenerateAsync(generate);
Console.WriteLine($"  Created  instance={created.InstanceId} replayed={created.Replayed}");

// The acknowledgement was lost; the caller retries the exact same request.
KeyMutationResult retried = await store.GenerateAsync(generate);
Console.WriteLine($"  Retried  instance={retried.InstanceId} replayed={retried.Replayed}");
Console.WriteLine($"  Keys in namespace: {(await store.ListAsync()).Count}");

// Reusing the id for a DIFFERENT request is a conflict, not a silent overwrite.
try
{
    await store.GenerateAsync(new KeyGenerateRequest(signingOperation, "other-key", KeyType.P256));
}
catch (KeyStoreException ex) when (ex.Error == KeyStoreError.IdempotencyConflict)
{
    Console.WriteLine($"  Conflicting reuse → {ex.Error}");
}

// The durable receipt answers "did my mutation land?" without re-issuing it —
// which matters most for import, where re-issuing means re-sending a secret.
KeyMutationOutcome? outcome = await store.GetMutationOutcomeAsync(KeyMutationKind.Generate, signingOperation);
if (outcome is KeyGeneratedOutcome generated)
{
    Console.WriteLine($"  Receipt  kind={generated.Kind} at={generated.RecordedAt:O}");
    Console.WriteLine($"           alias={generated.Info.Alias} instance={generated.InstanceId}");
}

// -------------------------------------------------------
// 3. Sign with the encoding named in the request
// -------------------------------------------------------
Console.WriteLine("\n=== 3. Algorithm- and encoding-bearing signing ===");

var payload = "the payload to sign"u8.ToArray();
StoredKeyInfo? info = await store.GetInfoAsync("signing-key", created.InstanceId);

byte[] joseSignature = await store.SignAsync(
    new KeySignRequest("signing-key", created.InstanceId, KeyStoreAlgorithms.Es256P1363, payload));
byte[] x509Signature = await store.SignAsync(
    new KeySignRequest("signing-key", created.InstanceId, KeyStoreAlgorithms.Es256Der, payload));

Console.WriteLine($"  es256-p1363 → {joseSignature.Length} bytes (JOSE / COSE / WebAuthn)");
Console.WriteLine($"  es256-der   → {x509Signature.Length} bytes (X.509 / CMS)");
Console.WriteLine($"  P1363 verifies as P1363: " +
    cryptoProvider.Verify(KeyType.P256, info!.PublicKey, payload, joseSignature, EcdsaSignatureFormat.IeeeP1363));
Console.WriteLine($"  P1363 verifies as DER:   " +
    cryptoProvider.Verify(KeyType.P256, info.PublicKey, payload, joseSignature, EcdsaSignatureFormat.Der));

// An unadvertised combination is refused before any backend work — never
// downgraded to a "close enough" curve, hash, or encoding.
try
{
    await store.SignAsync(new KeySignRequest(
        "signing-key", created.InstanceId, KeyStoreAlgorithms.Es384P1363, payload));
}
catch (KeyStoreException ex)
{
    Console.WriteLine($"  Wrong curve for the key → {ex.Error} (RetryAfter: {ex.RetryAfter?.ToString() ?? "none"})");
}

// -------------------------------------------------------
// 4. Key agreement by reference
// -------------------------------------------------------
Console.WriteLine("\n=== 4. Key agreement (raw Z, no KDF) ===");

var agreementOperation = new KeyOperationId(Guid.NewGuid().ToString("N"));
KeyMutationResult agreementKey = await store.GenerateAsync(
    new KeyGenerateRequest(agreementOperation, "agreement-key", KeyType.X25519));

using var peer = keyGenerator.Generate(KeyType.X25519);
var agreement = new KeyAgreementRequest(
    "agreement-key", agreementKey.InstanceId, KeyStoreAlgorithms.EcdhX25519, peer.PublicKey);
byte[] z = await store.DeriveSharedSecretAsync(agreement);

Console.WriteLine($"  PeerPublicKey: {agreement.PeerPublicKey.Length} bytes in the curve's canonical encoding");
Console.WriteLine($"  Z: {z.Length} bytes — apply Concat KDF / HKDF before use as keying material");

// -------------------------------------------------------
// 5. One-way import: the caller stops being able to read the secret
// -------------------------------------------------------
Console.WriteLine("\n=== 5. Import ownership transfer ===");

var externalKey = keyGenerator.Generate(KeyType.Ed25519);
TransferableKeyMaterial material = TransferableKeyMaterial.FromKeyPair(externalKey);
externalKey.Dispose(); // the caller's own copy is destroyed straight away

Console.WriteLine($"  Material: keyType={material.KeyType} publicKey={material.PublicKey.Length} bytes " +
    $"consumed={material.IsConsumed}");

var importOperation = new KeyOperationId(Guid.NewGuid().ToString("N"));
KeyMutationResult imported = await store.ImportAsync(
    new KeyImportRequest(importOperation, "imported-key", material));

Console.WriteLine($"  Imported instance={imported.InstanceId}; material consumed={material.IsConsumed}");
try
{
    _ = material.PublicKey;
}
catch (ObjectDisposedException)
{
    Console.WriteLine("  The transferred material is permanently unreadable — there is no export path.");
}

if (await store.GetMutationOutcomeAsync(KeyMutationKind.Import, importOperation) is KeyImportedOutcome importedOutcome)
    Console.WriteLine($"  Receipt  alias={importedOutcome.Info.Alias} instance={importedOutcome.InstanceId}");

// TransferableKeyMaterial.FromRawKey is the same transfer from raw bytes.
// `using` guarantees the secret is destroyed even if the import never happens.
using (var unused = TransferableKeyMaterial.FromRawKey(
    KeyType.Ed25519, imported.Info.PublicKey, new byte[32]))
{
    Console.WriteLine($"  FromRawKey also available (consumed={unused.IsConsumed})");
}

// -------------------------------------------------------
// 5b. The other side of the transfer: what a store's acceptance path looks like
// -------------------------------------------------------
// Everything above is the *caller's* half. This is the half an ICapableKeyStore implements —
// including one written outside this library, against an HSM, a KMS, or Vault. The store never
// receives a getter: it supplies a KeyMaterialReader<T> and NetCrypto hands the material to it
// exactly once, then zeroizes the buffer and latches the caller's object unreadable, whether or
// not the reader below succeeded.
Console.WriteLine("\n=== 5b. The store-side acceptance path ===");

using var arriving = keyGenerator.Generate(KeyType.Ed25519);
var arrivingMaterial = TransferableKeyMaterial.FromKeyPair(arriving);

// A real custody backend wraps here (AES-KWP under the custodian's wrapping key) and ships the
// ciphertext. What matters for the contract is the shape: the private bytes are a
// ReadOnlySpan<byte> that is valid only for this call, and any copy the store keeps is the
// store's own to zeroize. The reader must not call back into the material it is reading.
// A real store also derives the public key from these bytes here and rejects a mismatch
// (README implementor rule 13) — inside the reader is the only place it still can.
KeyMaterialReader<string> acceptIntoCustody = (keyType, publicKey, privateKey) =>
    $"wrapped {keyType} secret ({privateKey.Length} bytes) for public key of {publicKey.Length} bytes";

string custodyReceipt = arrivingMaterial.Consume(acceptIntoCustody);

Console.WriteLine($"  Store read the material once: {custodyReceipt}");
Console.WriteLine($"  Caller's object afterwards: consumed={arrivingMaterial.IsConsumed}");

// The replay path. A store that recognizes an already-applied import must NOT read the secret
// again — but must not leave a live copy with the caller either. Discard() is that: destroy
// without reading.
using var replayedKey = keyGenerator.Generate(KeyType.Ed25519);
var replayedMaterial = TransferableKeyMaterial.FromKeyPair(replayedKey);
replayedMaterial.Discard();
Console.WriteLine($"  Replay path — Discard() destroyed it unread: consumed={replayedMaterial.IsConsumed}");

// -------------------------------------------------------
// 6. BBS multi-message signing by reference
// -------------------------------------------------------
Console.WriteLine("\n=== 6. BBS by reference ===");

// Advertised exactly when the platform can do it — a store never claims a
// capability it cannot honor, and never advertises plain BLS signing as BBS.
if (capabilities.Find(KeyType.Bls12381G2, KeyStoreOperation.BbsSign, KeyStoreAlgorithms.BbsBls12381Sha256) is not null)
{
    KeyMutationResult bbsKey = await store.GenerateAsync(new KeyGenerateRequest(
        new KeyOperationId(Guid.NewGuid().ToString("N")), "bbs-key", KeyType.Bls12381G2));

    byte[][] claims =
    [
        "given-name=Ada"u8.ToArray(),
        "family-name=Lovelace"u8.ToArray(),
        "birth-year=1815"u8.ToArray(),
    ];
    var header = "mandatory-disclosure"u8.ToArray();

    byte[] bbsSignature = await store.SignBbsAsync(new KeyBbsSignRequest(
        "bbs-key", bbsKey.InstanceId, KeyStoreAlgorithms.BbsBls12381Sha256,
        claims.Select(c => new ReadOnlyMemory<byte>(c)).ToList(), header));

    StoredKeyInfo? bbsInfo = await store.GetInfoAsync("bbs-key", bbsKey.InstanceId);
    Console.WriteLine($"  Signed {claims.Length} messages → {bbsSignature.Length} bytes");
    Console.WriteLine($"  Verifies: {bbsProvider.Verify(bbsInfo!.PublicKey, bbsSignature, claims, header)}");
}
else
{
    // The supported BBS-absent mode: discovery told us, so nothing failed.
    Console.WriteLine("  BBS is not available on this platform — it is simply not advertised.");
}

// -------------------------------------------------------
// 7. Namespace scoping is authorization, not naming
// -------------------------------------------------------
Console.WriteLine("\n=== 7. Namespace isolation ===");

Console.WriteLine($"  issuer sees:    {string.Join(", ", await issuer.ListAsync())}");
Console.WriteLine($"  neighbour sees: [{string.Join(", ", await neighbour.ListAsync())}]");

try
{
    await neighbour.SignAsync(new KeySignRequest(
        "signing-key", created.InstanceId, KeyStoreAlgorithms.Es256P1363, payload));
}
catch (KeyNotFoundException)
{
    Console.WriteLine("  The neighbouring namespace cannot sign with the issuer's key.");
}

// -------------------------------------------------------
// 8. Instance identity survives alias reuse
// -------------------------------------------------------
Console.WriteLine("\n=== 8. Instance identity ===");

var deleteOperation = new KeyOperationId(Guid.NewGuid().ToString("N"));
KeyDeleteResult deleteResult = await store.DeleteAsync(
    new KeyDeleteRequest(deleteOperation, "signing-key", created.InstanceId));
Console.WriteLine($"  Deleted={deleteResult.Deleted} replayed={deleteResult.Replayed}");

if (await store.GetMutationOutcomeAsync(KeyMutationKind.Delete, deleteOperation) is KeyDeletionOutcome deletion)
    Console.WriteLine($"  Receipt  deleted={deletion.Deleted} instance={deletion.InstanceId}");

// The alias is recreated, holding a genuinely different key.
KeyMutationResult recreated = await store.GenerateAsync(new KeyGenerateRequest(
    new KeyOperationId(Guid.NewGuid().ToString("N")), "signing-key", KeyType.P256));
Console.WriteLine($"  Recreated instance={recreated.InstanceId} (was {created.InstanceId})");

try
{
    // A stale reference must fail rather than silently sign under the new key.
    await store.SignAsync(new KeySignRequest(
        "signing-key", created.InstanceId, KeyStoreAlgorithms.Es256P1363, payload));
}
catch (KeyNotFoundException)
{
    Console.WriteLine("  A stale KeyInstanceId is rejected — alias rebinding cannot go unnoticed.");
}

// -------------------------------------------------------
// 9. The inherited IKeyStore surface still works, unchanged
// -------------------------------------------------------
Console.WriteLine("\n=== 9. The legacy IKeyStore surface ===");

IKeyStore legacy = store;
await legacy.GenerateAsync("legacy-key", KeyType.Secp256k1);
ISigner signer = await legacy.CreateSignerAsync("legacy-key");
byte[] legacySignature = await signer.SignAsync(payload);
RecoverableSignature recoverable = await legacy.SignDigestAsync("legacy-key", new byte[32]);
StoredKeyInfo? legacyInfo = await legacy.GetInfoAsync("legacy-key");
byte[] legacyZ = await legacy.DeriveSharedSecretAsync("agreement-key", peer.PublicKey);
_ = await legacy.ImportAsync("adopted-key", keyGenerator.Generate(KeyType.Ed25519));

Console.WriteLine($"  Signer:          {signer.KeyType}, {legacySignature.Length}-byte signature");
Console.WriteLine($"  Recoverable:     recid={recoverable.RecoveryId}");
Console.WriteLine($"  Info carries an instance id: {legacyInfo!.InstanceId is not null}");
Console.WriteLine($"  Same Z as the capable path:  {legacyZ.AsSpan().SequenceEqual(z)}");
Console.WriteLine($"  Deleted legacy-key: {await legacy.DeleteAsync("legacy-key")}");

Console.WriteLine("\nCapable key store sample complete.");
