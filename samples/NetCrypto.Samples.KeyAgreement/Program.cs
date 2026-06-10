using System.Security.Cryptography;
using System.Text;
using NetCrypto;

// ============================================================
// NetCrypto Samples — Key Agreement (ECDH) and Key Derivation
// ============================================================
//
// Two parties — Alice and Bob — agree on a shared key without ever
// sending secret material over the wire. Each side combines its own
// PRIVATE key with the other side's PUBLIC key; ECDH guarantees both
// computations land on the same value.

var keyGen = new DefaultKeyGenerator();
var crypto = new DefaultCryptoProvider();

// -------------------------------------------------------
// 1. X25519 KeyAgreement — the one-call convenience path
// -------------------------------------------------------
Console.WriteLine("=== X25519 KeyAgreement (HKDF-SHA256 convenience) ===");

// Each party generates its own X25519 pair and publishes only the
// public half. The private half never leaves the party that made it.
var aliceX = keyGen.Generate(KeyType.X25519);
var bobX = keyGen.Generate(KeyType.X25519);

// KeyAgreement runs X25519 ECDH and then HKDF-SHA256 internally,
// returning a ready-to-use 32-byte key. This covers the common
// DIDComm/did:peer case where you just need "a good symmetric key".
var aliceKey = crypto.KeyAgreement(aliceX.PrivateKey, bobX.PublicKey);
var bobKey = crypto.KeyAgreement(bobX.PrivateKey, aliceX.PublicKey);

Console.WriteLine($"  Alice derives: {Convert.ToHexString(aliceKey)}");
Console.WriteLine($"  Bob derives:   {Convert.ToHexString(bobKey)}");
Check(aliceKey.AsSpan().SequenceEqual(bobKey), "both directions yield the identical 32-byte key");
Console.WriteLine();

// -------------------------------------------------------
// 2. Raw DeriveSharedSecret — X25519
// -------------------------------------------------------
Console.WriteLine("=== Raw shared secret Z — X25519 ===");

// When a protocol (JOSE ECDH-ES, ECDH-1PU, TLS-like designs) mandates
// its OWN key-derivation step, you need the raw ECDH output "Z" with
// no KDF applied. That is exactly what DeriveSharedSecret returns —
// Z is NOT uniformly random and must never be used as a key directly.
var aliceZx = crypto.DeriveSharedSecret(KeyType.X25519, aliceX.PrivateKey, bobX.PublicKey);
var bobZx = crypto.DeriveSharedSecret(KeyType.X25519, bobX.PrivateKey, aliceX.PublicKey);

Console.WriteLine($"  Alice Z ({aliceZx.Length} bytes): {Convert.ToHexString(aliceZx)}");
Console.WriteLine($"  Bob   Z ({bobZx.Length} bytes): {Convert.ToHexString(bobZx)}");
Check(aliceZx.AsSpan().SequenceEqual(bobZx), "X25519 raw Z matches on both sides");
Console.WriteLine();

// -------------------------------------------------------
// 3. Raw DeriveSharedSecret — P-256
// -------------------------------------------------------
Console.WriteLine("=== Raw shared secret Z — P-256 ===");

// The same call works on the NIST curves (P-256/P-384), which the
// X25519-only KeyAgreement convenience does not cover. NetCrypto's
// P-curve public keys are SEC1 compressed points (33 bytes for P-256);
// DeriveSharedSecret accepts compressed or uncompressed encodings.
var aliceP = keyGen.Generate(KeyType.P256);
var bobP = keyGen.Generate(KeyType.P256);

var aliceZp = crypto.DeriveSharedSecret(KeyType.P256, aliceP.PrivateKey, bobP.PublicKey);
var bobZp = crypto.DeriveSharedSecret(KeyType.P256, bobP.PrivateKey, aliceP.PublicKey);

Console.WriteLine($"  Alice Z ({aliceZp.Length} bytes): {Convert.ToHexString(aliceZp)}");
Console.WriteLine($"  Bob   Z ({bobZp.Length} bytes): {Convert.ToHexString(bobZp)}");
Check(aliceZp.AsSpan().SequenceEqual(bobZp), "P-256 raw Z matches on both sides");
Console.WriteLine();

// -------------------------------------------------------
// 3b. EcPointValidator — the invalid-curve attack defense
// -------------------------------------------------------
Console.WriteLine("=== EcPointValidator.EnsureOnCurve ===");

// Off-curve (x, y) coordinates from a malicious peer leak your static
// private key during NIST/secp256k1 ECDH (the invalid-curve attack);
// RFC 7518 §6.2.2 mandates validating before agreement. NetCrypto's own
// import paths do this internally — call EnsureOnCurve yourself when a
// peer key arrives as raw big-endian coordinates (e.g. a JWE "epk").
var gx = Convert.FromHexString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
var gy = Convert.FromHexString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
EcPointValidator.EnsureOnCurve(KeyType.Secp256k1, gx, gy); // the secp256k1 generator G — on-curve, returns silently
Check(true, "a genuine on-curve point (secp256k1 G) passes EnsureOnCurve");

gy[31] ^= 0x01; // flip one bit of y — (x, y) is no longer a curve point
try { EcPointValidator.EnsureOnCurve(KeyType.Secp256k1, gx, gy); Check(false, "off-curve point must be rejected"); }
catch (CryptographicException) { Check(true, "off-curve (x, y) throws CryptographicException before any ECDH runs"); }
Console.WriteLine();

// -------------------------------------------------------
// 4. Z + Concat KDF — the JOSE ECDH-ES recipe
// -------------------------------------------------------
Console.WriteLine("=== Concat KDF over Z (JOSE ECDH-ES style) ===");

// Concat KDF (NIST SP 800-56A §5.8.1) is the KDF that RFC 7518 §4.6
// mandates for JOSE ECDH-ES. This is what didcomm-dotnet does when it
// builds a JWE: the "enc" algorithm name and the apu/apv party labels
// are mixed into the derivation, so the key is cryptographically bound
// to this algorithm and these two parties — reusing Z for a different
// algorithm or peer yields a completely different key.
var algorithmId = Encoding.UTF8.GetBytes("A256GCM"); // JOSE "enc" header value
var apu = Encoding.UTF8.GetBytes("Alice");           // PartyUInfo: producer
var apv = Encoding.UTF8.GetBytes("Bob");             // PartyVInfo: consumer
byte[] suppPubInfo = [0x00, 0x00, 0x01, 0x00];       // keydatalen: 256 bits, big-endian

var aliceCek = ConcatKdf.DeriveKey(aliceZx, algorithmId, apu, apv, suppPubInfo, ReadOnlySpan<byte>.Empty, keyDataLen: 32);
var bobCek = ConcatKdf.DeriveKey(bobZx, algorithmId, apu, apv, suppPubInfo, ReadOnlySpan<byte>.Empty, keyDataLen: 32);

Console.WriteLine($"  Alice CEK: {Convert.ToHexString(aliceCek)}");
Console.WriteLine($"  Bob CEK:   {Convert.ToHexString(bobCek)}");
Check(aliceCek.AsSpan().SequenceEqual(bobCek), "Concat KDF yields the same content-encryption key");
Console.WriteLine();

// -------------------------------------------------------
// 5. Z + HKDF — the RFC 5869 alternative
// -------------------------------------------------------
Console.WriteLine("=== HKDF over Z (RFC 5869) ===");

// HKDF is the right choice when you are NOT bound to JOSE — e.g.
// Noise-style protocols or application-defined session keys. The salt
// and info play the same binding role as apu/apv above: both sides
// must use identical values, usually fixed by the protocol spec.
var salt = Encoding.UTF8.GetBytes("sample-protocol-v1");
var info = Encoding.UTF8.GetBytes("alice->bob session key");

var aliceHkdf = Hkdf.DeriveKey(HashAlgorithmName.SHA256, aliceZp, outputLength: 32, salt, info);
var bobHkdf = Hkdf.DeriveKey(HashAlgorithmName.SHA256, bobZp, outputLength: 32, salt, info);

Console.WriteLine($"  Alice key: {Convert.ToHexString(aliceHkdf)}");
Console.WriteLine($"  Bob key:   {Convert.ToHexString(bobHkdf)}");
Check(aliceHkdf.AsSpan().SequenceEqual(bobHkdf), "HKDF yields the same session key from the P-256 Z");

// DeriveKey fuses the two RFC 5869 stages; protocols that cache the
// pseudorandom key and expand it repeatedly (Noise, ratchet designs)
// call Extract once and Expand per output — the result is identical.
var prk = Hkdf.Extract(HashAlgorithmName.SHA256, aliceZp, salt);
var expanded = Hkdf.Expand(HashAlgorithmName.SHA256, prk, outputLength: 32, info);
Check(expanded.AsSpan().SequenceEqual(aliceHkdf), "Extract then Expand equals the one-call DeriveKey");
Console.WriteLine();

// -------------------------------------------------------
// The boundary: NetCrypto stops at Z + KDFs. Full ECDH-ES / ECDH-1PU
// assembly — ephemeral key handling, the JWE "epk" header, Ze ‖ Zs
// concatenation for 1PU — lives in consumer libraries such as
// didcomm-dotnet, which compose it from exactly the calls shown here.
// -------------------------------------------------------
Console.WriteLine("Done! All key agreement examples completed successfully.");
return;

// Prints each expectation; any failure exits non-zero so CI catches it.
static void Check(bool condition, string what)
{
    Console.WriteLine($"  {(condition ? "OK" : "FAILED")}: {what}");
    if (!condition)
        Environment.Exit(1);
}
