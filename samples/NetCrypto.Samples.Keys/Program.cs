using System.Security.Cryptography;
using NetCrypto;

// ============================================================
// NetCrypto Samples — Keys
// Key generation, restoration, public-key references,
// multibase encoding, and Ed25519 -> X25519 derivation.
// ============================================================

// IKeyGenerator is the only door to key material. Code against the
// interface so a hardware-backed generator can be swapped in later.
IKeyGenerator keyGenerator = new DefaultKeyGenerator();

// -------------------------------------------------------
// 1. KeyType — every supported algorithm, one enum
// -------------------------------------------------------
// Each KeyType maps to a registered multicodec code; that code is what
// makes the multibase-encoded public key self-describing (a consumer can
// recover the key type from the encoded string alone, e.g. in did:key).
Console.WriteLine("=== 1. KeyType — generate one key per supported type ===");

foreach (var keyType in Enum.GetValues<KeyType>())
{
    var pair = keyGenerator.Generate(keyType);
    var codec = keyType.GetMulticodec();

    Console.WriteLine($"  {keyType,-10} pub {pair.PublicKey.Length,3} B  priv {pair.PrivateKey.Length,2} B  " +
                      $"multicodec 0x{codec:X4}  {pair.MultibasePublicKey[..14]}...");

    // The codec mapping must round-trip, otherwise encoded keys could not be decoded back.
    Check(KeyTypeExtensions.FromMulticodec(codec) == keyType, $"{keyType}: multicodec round-trips");
    // Generated public keys always come out in the canonical stored length
    // (raw for Edwards/Montgomery keys, compressed SEC1 for NIST/secp256k1).
    Check(keyType.IsValidKeyLength(pair.PublicKey.Length), $"{keyType}: canonical public key length");
}
Console.WriteLine();

// -------------------------------------------------------
// 2. KeyPair — properties and FromPrivateKey restoration
// -------------------------------------------------------
Console.WriteLine("=== 2. KeyPair — Generate / FromPrivateKey round-trip ===");

var ed25519 = keyGenerator.Generate(KeyType.Ed25519);

// A KeyPair is a plain value object: type + raw bytes. Never log the
// private key itself — its length is all a diagnostic ever needs.
Console.WriteLine($"  KeyType:           {ed25519.KeyType}");
Console.WriteLine($"  PublicKey (hex):   {Convert.ToHexString(ed25519.PublicKey)}");
Console.WriteLine($"  PrivateKey:        (kept secret, {ed25519.PrivateKey.Length} bytes)");
// MultibasePublicKey = base58btc("z") of multicodec-prefix + raw public key.
// This is the wire format DID documents and did:key identifiers use.
Console.WriteLine($"  MultibasePublicKey: {ed25519.MultibasePublicKey}");
Check(ed25519.MultibasePublicKey.StartsWith("z6Mk"), "Ed25519 multibase starts with z6Mk");

// Restoring from a stored private key (a vault, a seed backup) must
// reproduce exactly the same public identity — verify that it does.
var restored = keyGenerator.FromPrivateKey(KeyType.Ed25519, ed25519.PrivateKey);
Check(restored.PublicKey.AsSpan().SequenceEqual(ed25519.PublicKey), "restored pair has the same public key");
Console.WriteLine();

// -------------------------------------------------------
// 3. PublicKeyReference — the verifier's view of a key
// -------------------------------------------------------
Console.WriteLine("=== 3. PublicKeyReference — FromPublicKey (no private material) ===");

// A verifier only ever receives public bytes. FromPublicKey wraps them in
// a PublicKeyReference, a type that *cannot* carry a private key, so the
// compiler enforces the holder/verifier separation. The bytes must be the
// canonical encoding (compressed SEC1 point for EC types) and are validated —
// wrong lengths or off-curve points throw ArgumentException instead of
// propagating garbage into multibase/JWK output. Uncompressed EC points can
// be converted first with KeyTypeExtensions.NormalizeToCompressed.
var reference = keyGenerator.FromPublicKey(KeyType.Ed25519, ed25519.PublicKey);

Console.WriteLine($"  KeyType:            {reference.KeyType}");
Console.WriteLine($"  MultibasePublicKey: {reference.MultibasePublicKey}");
// Both sides must agree on the encoded form, or identifiers would diverge.
Check(reference.MultibasePublicKey == ed25519.MultibasePublicKey,
    "KeyPair and PublicKeyReference encode the same multibase string");
Console.WriteLine();

// -------------------------------------------------------
// 4. Ed25519 -> X25519 derivation — both forms agree
// -------------------------------------------------------
Console.WriteLine("=== 4. Ed25519 -> X25519 derivation (both forms) ===");

// One Ed25519 identity key can also encrypt: the same curve point maps to
// an X25519 key-agreement key (this is how did:key adds a keyAgreement
// entry without a second key ceremony).
//
// Form A — the key holder has the full pair, so it can derive the X25519
// *private* key too (needed to actually decrypt).
var xPair = keyGenerator.DeriveX25519FromEd25519(ed25519);
Console.WriteLine($"  Holder-side  (full pair):  {xPair.KeyType}, {xPair.MultibasePublicKey}");

// Form B — a resolver only sees the Ed25519 public key, so it derives just
// the X25519 public key via the Edwards->Montgomery birational map.
var xReference = keyGenerator.DeriveX25519PublicKeyFromEd25519(ed25519.PublicKey);
Console.WriteLine($"  Resolver-side (public-only): {xReference.KeyType}, {xReference.MultibasePublicKey}");

// If the two forms disagreed, the resolver would publish an encryption key
// the holder cannot use — they must land on the identical public key.
Check(xPair.PublicKey.AsSpan().SequenceEqual(xReference.PublicKey), "both derivations yield the same X25519 public key");
Check(xPair.MultibasePublicKey.StartsWith("z6LS"), "X25519 multibase starts with z6LS");
Console.WriteLine();

// -------------------------------------------------------
// 5. KeyTypeExtensions — validation and normalization helpers
// -------------------------------------------------------
Console.WriteLine("=== 5. KeyTypeExtensions — NormalizeToCompressed / IsValidEcPoint ===");

// Other stacks (BCL ECDsa, HSMs, JOSE) often hand you *uncompressed* SEC1
// points (0x04 || X || Y, 65 bytes for P-256). NetCrypto stores compressed
// points, so normalize foreign keys before comparing or encoding them.
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var ec = ecdsa.ExportParameters(includePrivateParameters: true);
var uncompressed = new byte[65];
uncompressed[0] = 0x04;
ec.Q.X!.CopyTo(uncompressed, 1);
ec.Q.Y!.CopyTo(uncompressed, 33);

var compressed = KeyType.P256.NormalizeToCompressed(uncompressed);
Console.WriteLine($"  Uncompressed {uncompressed.Length} B -> compressed {compressed.Length} B (prefix 0x{compressed[0]:X2})");
// 65 bytes is valid SEC1 but not the canonical stored length — only 33 is.
Check(!KeyType.P256.IsValidKeyLength(uncompressed.Length) && KeyType.P256.IsValidKeyLength(compressed.Length),
    "only the compressed form has the canonical P-256 length");

// Restoring from the same private key must reproduce the normalized point —
// proof that NormalizeToCompressed and the generator agree on the format.
var p256Restored = keyGenerator.FromPrivateKey(KeyType.P256, ec.D!);
Check(p256Restored.PublicKey.AsSpan().SequenceEqual(compressed), "FromPrivateKey matches the normalized point");

// IsValidEcPoint defends against the invalid-curve attack: always check
// foreign EC keys before using them, or a malicious off-curve point can
// leak your private key during ECDH. (x, y) = (1, 1) is not on P-256.
var offCurve = new byte[65];
offCurve[0] = 0x04;
offCurve[32] = 0x01; // x = 1
offCurve[64] = 0x01; // y = 1
Console.WriteLine($"  Genuine point on curve:  {KeyType.P256.IsValidEcPoint(compressed)}");
Console.WriteLine($"  Off-curve (1,1) point:   {KeyType.P256.IsValidEcPoint(offCurve)}");
Check(KeyType.P256.IsValidEcPoint(compressed), "genuine P-256 point accepted");
Check(!KeyType.P256.IsValidEcPoint(offCurve), "off-curve point rejected");
// Edwards/Montgomery encodings are on-curve by construction, so for
// non-NIST/secp256k1 types the check is a no-op that returns true.
Check(KeyType.Ed25519.IsValidEcPoint(ed25519.PublicKey), "non-EC types skip point validation");
Console.WriteLine();

Console.WriteLine("Done! All key examples completed successfully.");
return 0;

// Prints each expectation; any failure ends the program with exit code 1
// so CI (and you) cannot miss a broken assumption.
static void Check(bool condition, string what)
{
    Console.WriteLine($"  [{(condition ? "ok" : "FAIL")}] {what}");
    if (!condition) Environment.Exit(1);
}
