using NetCrypto;

// ============================================================
// NetCrypto Samples — Signing
// ============================================================
// ICryptoProvider / DefaultCryptoProvider: Sign and Verify for
// every signing-capable KeyType, plus EcdsaSignatureFormat —
// the same P-256 key emitting DER and IEEE P1363 signatures.

// Code against the ICryptoProvider interface (not the concrete class) so the
// crypto backend can be swapped — e.g. for an HSM-backed provider — without
// touching any calling code. DefaultCryptoProvider is the stock software one.
ICryptoProvider crypto = new DefaultCryptoProvider();
IKeyGenerator keyGen = new DefaultKeyGenerator();

var message = "NetCrypto signing sample"u8.ToArray();

// -------------------------------------------------------
// 1. Sign / Verify round-trip for each signing-capable key type
// -------------------------------------------------------
Console.WriteLine("=== Sign / Verify per key type ===");

// X25519 is deliberately missing from this list: it is a key-agreement-only
// curve and cannot sign. Every other KeyType supports Sign/Verify.
KeyType[] signingKeyTypes =
[
    KeyType.Ed25519,    // EdDSA — fixed 64-byte signature
    KeyType.P256,       // ECDSA over NIST P-256 (JOSE "ES256")
    KeyType.P384,       // ECDSA over NIST P-384 (JOSE "ES384")
    KeyType.P521,       // ECDSA over NIST P-521 (JOSE "ES512")
    KeyType.Secp256k1,  // ECDSA over secp256k1 — always 64-byte compact R‖S
    KeyType.Bls12381G1, // BLS — public key in G1 (48 B), signature in G2 (96 B)
    KeyType.Bls12381G2, // BLS — public key in G2 (96 B), signature in G1 (48 B)
];

foreach (var keyType in signingKeyTypes)
{
    // One Sign/Verify API covers every algorithm: the KeyType selects the
    // algorithm, so callers never bind to a specific crypto library.
    var keyPair = keyGen.Generate(keyType);
    var signature = crypto.Sign(keyType, keyPair.PrivateKey, message);

    // A genuine signature must verify against the matching public key...
    var valid = crypto.Verify(keyType, keyPair.PublicKey, message, signature);

    // ...and must fail once the data changes. Verify reports tampering by
    // returning false — never by throwing — so callers have one code path
    // for "bad signature" regardless of why it is bad.
    var tampered = crypto.Verify(keyType, keyPair.PublicKey, "tampered!"u8, signature);

    Console.WriteLine($"  {keyType,-10}  sig {signature.Length,3} bytes  verify={valid}  tamperedVerify={tampered}");
    Check(valid, $"{keyType} signature verifies");
    Check(!tampered, $"{keyType} rejects tampered data");
}
Console.WriteLine();

// -------------------------------------------------------
// 2. EcdsaSignatureFormat — the SAME P-256 key, two wire formats
// -------------------------------------------------------
Console.WriteLine("=== EcdsaSignatureFormat — DER vs IEEE P1363 ===");

var p256 = keyGen.Generate(KeyType.P256);

// DER wraps r and s in an ASN.1 SEQUENCE whose length varies (70-72 bytes
// for P-256, depending on leading-zero padding of r and s). X.509, CMS, and
// generic DID proofs expect DER, so it is the library default.
var derSig = crypto.Sign(KeyType.P256, p256.PrivateKey, message, EcdsaSignatureFormat.Der);

// IEEE P1363 is the raw concatenation R‖S, each value zero-padded to the
// curve's field width: exactly 32 + 32 = 64 bytes for P-256. JOSE / JWS
// (RFC 7515 §3.4), COSE, and WebAuthn mandate this format because the
// signature is base64url-encoded straight into the token and consumers
// split it at the midpoint without an ASN.1 parser — that only works when
// the length is fixed and known from the curve alone.
var p1363Sig = crypto.Sign(KeyType.P256, p256.PrivateKey, message, EcdsaSignatureFormat.IeeeP1363);

Console.WriteLine($"  DER        signature: {derSig.Length} bytes (variable — ASN.1 SEQUENCE)");
Console.WriteLine($"  IEEE P1363 signature: {p1363Sig.Length} bytes (fixed — 2 x 32-byte field width)");
Check(p1363Sig.Length == 64, "P-256 IEEE P1363 signature is exactly 64 bytes");

// Verification takes the same format flag: state the format the signature
// was produced in and the round-trip succeeds.
var derOk = crypto.Verify(KeyType.P256, p256.PublicKey, message, derSig, EcdsaSignatureFormat.Der);
var p1363Ok = crypto.Verify(KeyType.P256, p256.PublicKey, message, p1363Sig, EcdsaSignatureFormat.IeeeP1363);

Console.WriteLine($"  Verify DER   signature as Der       : {derOk}");
Console.WriteLine($"  Verify P1363 signature as IeeeP1363 : {p1363Ok}");
Check(derOk, "DER signature verifies as Der");
Check(p1363Ok, "IEEE P1363 signature verifies as IeeeP1363");
Console.WriteLine();

// -------------------------------------------------------
// 3. Cross-format Verify returns false (it never throws)
// -------------------------------------------------------
Console.WriteLine("=== Cross-format verification ===");

// The bytes below are perfectly valid signatures — but presented under the
// wrong format they cannot be decoded into (r, s), so Verify returns false.
// Format mismatch is treated like any other invalid signature, keeping a
// single, predictable failure path for callers.
var derAsP1363 = crypto.Verify(KeyType.P256, p256.PublicKey, message, derSig, EcdsaSignatureFormat.IeeeP1363);
var p1363AsDer = crypto.Verify(KeyType.P256, p256.PublicKey, message, p1363Sig, EcdsaSignatureFormat.Der);

Console.WriteLine($"  Verify DER   signature as IeeeP1363 : {derAsP1363} (expected False)");
Console.WriteLine($"  Verify P1363 signature as Der       : {p1363AsDer} (expected False)");
Check(!derAsP1363, "DER bytes do not verify under IeeeP1363");
Check(!p1363AsDer, "IEEE P1363 bytes do not verify under Der");
Console.WriteLine();

Console.WriteLine("Done! All signing examples completed successfully.");
return 0;

// Halt with a non-zero exit code on any failed expectation so an automated
// run of this sample (e.g. in CI) is marked as failed.
static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
