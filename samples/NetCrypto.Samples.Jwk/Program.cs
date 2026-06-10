using Microsoft.IdentityModel.Tokens;
using NetCrypto;

// ============================================================
// NetCrypto Samples — JWK conversion
// ============================================================
// JSON Web Keys (RFC 7517) are how keys travel in JOSE, DID
// documents and OIDC metadata. JwkConverter maps NetCrypto's raw
// key model (KeyType + raw bytes) to and from JsonWebKey, so the
// wire format never leaks into the rest of your code.

var keyGen = new DefaultKeyGenerator();

// -------------------------------------------------------
// 1. Public JWK from raw bytes — ToPublicJwk(KeyType, byte[])
// -------------------------------------------------------
// Use this overload when all you have is a public key (e.g. one
// received from a peer) — no KeyPair, and no private material.
Console.WriteLine("=== 1. Public JWK from raw public key bytes ===");

var ed = keyGen.Generate(KeyType.Ed25519);
var edPublicJwk = JwkConverter.ToPublicJwk(KeyType.Ed25519, ed.PublicKey);

// Ed25519 maps to kty "OKP" (octet key pair); the key bytes land
// in 'x' as unpadded base64url, exactly as RFC 8037 requires.
Console.WriteLine($"  Ed25519 public JWK: {Render(edPublicJwk)}");
Check(edPublicJwk.Kty == "OKP" && edPublicJwk.Crv == "Ed25519", "Ed25519 maps to OKP/Ed25519");
// A public JWK must never carry 'd' (the private key) — handing
// it to a verifier or a directory must not leak signing power.
Check(edPublicJwk.D == null, "public JWK has no 'd' (D == null)");

// -------------------------------------------------------
// 2. Public JWK from a KeyPair — ToPublicJwk(KeyPair)
// -------------------------------------------------------
// Same conversion, but the KeyType travels inside the KeyPair so
// you cannot mismatch type and bytes by accident.
Console.WriteLine("=== 2. Public JWK from a KeyPair (EC curve) ===");

var p256 = keyGen.Generate(KeyType.P256);
var p256PublicJwk = JwkConverter.ToPublicJwk(p256);

// NIST curves map to kty "EC". NetCrypto stores EC public keys as
// compressed SEC1 points (prefix + x), so the converter recovers
// the full (x, y) pair for the JWK — JOSE requires both coordinates.
Console.WriteLine($"  P-256 public JWK: {Render(p256PublicJwk)}");
Check(p256PublicJwk.Kty == "EC" && p256PublicJwk.Crv == "P-256", "P-256 maps to EC/P-256");
Check(!string.IsNullOrEmpty(p256PublicJwk.X) && !string.IsNullOrEmpty(p256PublicJwk.Y), "EC JWK carries both x and y");

// -------------------------------------------------------
// 3. Private JWK — ToPrivateJwk(KeyPair)
// -------------------------------------------------------
// Only for export to a place you trust with the private key
// (a vault, a sealed config). The single difference from the
// public form is the added 'd' member.
Console.WriteLine("=== 3. Private JWK — the 'd' member ===");

var edPrivateJwk = JwkConverter.ToPrivateJwk(ed);
Console.WriteLine($"  Ed25519 private JWK: {Render(edPrivateJwk)}");
Console.WriteLine($"  public  jwk.D: {(edPublicJwk.D == null ? "null" : "present")}  |  private jwk.D: {(edPrivateJwk.D == null ? "null" : "present")}");
Check(edPrivateJwk.D != null, "private JWK carries 'd' (D != null)");
Check(edPrivateJwk.X == edPublicJwk.X, "private JWK keeps the same public part");

// -------------------------------------------------------
// 4. Round-trip — ExtractPublicKey(JsonWebKey)
// -------------------------------------------------------
// ExtractPublicKey is the inverse of ToPublicJwk: parse a JWK you
// received and get back (KeyType, raw bytes) for use with the rest
// of NetCrypto (verify, ECDH, ...). For EC keys it also validates
// the point is on the stated curve before you can touch it.
Console.WriteLine("=== 4. Round-trip: ToPublicJwk -> ExtractPublicKey ===");

var (edType, edBytes) = JwkConverter.ExtractPublicKey(edPublicJwk);
Console.WriteLine($"  OKP round-trip: KeyType={edType}, {edBytes.Length} bytes");
Check(edType == KeyType.Ed25519, "OKP round-trip preserves KeyType");
Check(edBytes.AsSpan().SequenceEqual(ed.PublicKey), "OKP round-trip preserves public key bytes");

var (p256Type, p256Bytes) = JwkConverter.ExtractPublicKey(p256PublicJwk);
Console.WriteLine($"  EC  round-trip: KeyType={p256Type}, {p256Bytes.Length} bytes (compressed SEC1)");
Check(p256Type == KeyType.P256, "EC round-trip preserves KeyType");
Check(p256Bytes.AsSpan().SequenceEqual(p256.PublicKey), "EC round-trip preserves public key bytes");

// -------------------------------------------------------
// 5. KeyPair convenience — ToPublicJwk() / ToPrivateJwk()
// -------------------------------------------------------
// KeyPair exposes the same conversions as instance methods, so
// everyday code reads naturally without naming JwkConverter.
Console.WriteLine("=== 5. KeyPair.ToPublicJwk() / ToPrivateJwk() ===");

var viaKeyPairPublic = p256.ToPublicJwk();
var viaKeyPairPrivate = p256.ToPrivateJwk();
Console.WriteLine($"  p256.ToPublicJwk():  {Render(viaKeyPairPublic)}");
Console.WriteLine($"  p256.ToPrivateJwk(): d {(viaKeyPairPrivate.D == null ? "absent" : "present")}");
Check(viaKeyPairPublic.X == p256PublicJwk.X && viaKeyPairPublic.Y == p256PublicJwk.Y, "convenience method matches JwkConverter output");
Check(viaKeyPairPublic.D == null && viaKeyPairPrivate.D != null, "convenience public/private split is the same");

Console.WriteLine();
Console.WriteLine("Done! All JWK conversion examples completed successfully.");
return 0;

// Render the JWK members we set as compact JSON, omitting absent
// ones — mirrors what the key looks like on the wire ('d' is
// truncated so a copy-pasted console log never leaks a full key).
static string Render(JsonWebKey jwk)
{
    var parts = new List<string> { $"\"kty\":\"{jwk.Kty}\"", $"\"crv\":\"{jwk.Crv}\"", $"\"x\":\"{jwk.X}\"" };
    if (jwk.Y != null) parts.Add($"\"y\":\"{jwk.Y}\"");
    if (jwk.D != null) parts.Add($"\"d\":\"{jwk.D[..6]}...\"");
    return "{" + string.Join(",", parts) + "}";
}

// Print each expectation; any failure aborts with a non-zero exit
// code so CI (and you) cannot mistake a broken sample for success.
static void Check(bool condition, string what)
{
    Console.WriteLine($"  {(condition ? "[ok]  " : "[FAIL]")} {what}");
    if (!condition) Environment.Exit(1);
}
