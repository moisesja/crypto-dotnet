using System.Security.Cryptography;
using NetCrypto;

// ============================================================
// NetCrypto Samples — Symmetric Encryption (AEAD + Key Wrap)
// ============================================================
//
// Every cipher here is an AEAD (Authenticated Encryption with Associated
// Data): decryption succeeds ONLY if the ciphertext, tag, and associated
// data are exactly what was produced at encryption. The associated data
// (AAD) is authenticated but NOT encrypted — use it for headers/metadata
// that must travel in the clear yet still be tamper-proof.

// The same plaintext and AAD are reused for all three AEADs so you can
// compare their parameter sizes directly.
var plaintext = "Attack at dawn — NetCrypto AEAD sample"u8.ToArray();
var aad = """{"alg":"dir","enc":"sample"}"""u8.ToArray();

// -------------------------------------------------------
// 1. AES-256-GCM (JOSE "A256GCM") — key 32, nonce 12, tag 16
// -------------------------------------------------------
Console.WriteLine("=== AES-256-GCM (A256GCM) ===");
// Each cipher type publishes its key/nonce/tag sizes as public constants, so a
// caller allocating the CEK and IV/nonce up front (as a JOSE builder must, before
// it can call Encrypt) validates against the source of truth instead of a hard-coded table.
Console.WriteLine($"  Sizes: key = {AesGcmCipher.KeySizeBytes} bytes, nonce = {AesGcmCipher.NonceSizeBytes} bytes, tag = {AesGcmCipher.TagSizeBytes} bytes");

// Keys and nonces come from a cryptographically secure RNG. A GCM nonce
// must NEVER be reused with the same key — reuse breaks both secrecy and
// authenticity — so generate a fresh one per message.
var gcmKey = RandomNumberGenerator.GetBytes(AesGcmCipher.KeySizeBytes);
var gcmNonce = RandomNumberGenerator.GetBytes(AesGcmCipher.NonceSizeBytes);

var (gcmCiphertext, gcmTag) = AesGcmCipher.Encrypt(gcmKey, gcmNonce, plaintext, aad);
Console.WriteLine($"  Ciphertext: {gcmCiphertext.Length} bytes (same length as plaintext — GCM is a stream construction)");
Console.WriteLine($"  Tag:        {Convert.ToHexString(gcmTag)}");

// Decrypt with the SAME key, nonce, and AAD; the tag is verified first.
var gcmRecovered = AesGcmCipher.Decrypt(gcmKey, gcmNonce, gcmCiphertext, gcmTag, aad);
Check(gcmRecovered.AsSpan().SequenceEqual(plaintext), "A256GCM round-trip recovers the plaintext");
Console.WriteLine();

// -------------------------------------------------------
// 2. AES-256-CBC + HMAC-SHA-512 (JOSE "A256CBC-HS512") — key 64, IV 16, tag 32
// -------------------------------------------------------
Console.WriteLine("=== AES-256-CBC + HMAC-SHA-512 (A256CBC-HS512) ===");
Console.WriteLine($"  Sizes: key = {AesCbcHmacCipher.KeySizeBytes} bytes, IV = {AesCbcHmacCipher.IvSizeBytes} bytes, tag = {AesCbcHmacCipher.TagSizeBytes} bytes");

// The 64-byte key is really two keys (RFC 7518 §5.2.2): the first 32 bytes
// MAC the data (HMAC-SHA-512), the last 32 bytes encrypt it (AES-256-CBC).
// That is why this AEAD needs twice the key material of the others.
var cbcKey = RandomNumberGenerator.GetBytes(AesCbcHmacCipher.KeySizeBytes);
var cbcIv = RandomNumberGenerator.GetBytes(AesCbcHmacCipher.IvSizeBytes);

var (cbcCiphertext, cbcTag) = AesCbcHmacCipher.Encrypt(cbcKey, cbcIv, plaintext, aad);
// CBC pads to a 16-byte block boundary, so the ciphertext grows — unlike GCM/XChaCha.
Console.WriteLine($"  Ciphertext: {cbcCiphertext.Length} bytes (plaintext {plaintext.Length} + PKCS#7 padding to a 16-byte block)");
Console.WriteLine($"  Tag:        {Convert.ToHexString(cbcTag)}");

var cbcRecovered = AesCbcHmacCipher.Decrypt(cbcKey, cbcIv, cbcCiphertext, cbcTag, aad);
Check(cbcRecovered.AsSpan().SequenceEqual(plaintext), "A256CBC-HS512 round-trip recovers the plaintext");
Console.WriteLine();

// -------------------------------------------------------
// 3. XChaCha20-Poly1305 (JOSE "XC20P") — key 32, nonce 24, tag 16
// -------------------------------------------------------
Console.WriteLine("=== XChaCha20-Poly1305 (XC20P) ===");
Console.WriteLine($"  Sizes: key = {XChaCha20Poly1305Cipher.KeySizeBytes} bytes, nonce = {XChaCha20Poly1305Cipher.NonceSizeBytes} bytes, tag = {XChaCha20Poly1305Cipher.TagSizeBytes} bytes");

// The 24-byte extended nonce is the whole point of XChaCha20: it is large
// enough that random nonces have no practical collision risk, so there is
// no counter to manage — ideal when many parties encrypt under one key.
var xKey = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.KeySizeBytes);
var xNonce = RandomNumberGenerator.GetBytes(XChaCha20Poly1305Cipher.NonceSizeBytes);

var (xCiphertext, xTag) = XChaCha20Poly1305Cipher.Encrypt(xKey, xNonce, plaintext, aad);
Console.WriteLine($"  Ciphertext: {xCiphertext.Length} bytes");
Console.WriteLine($"  Tag:        {Convert.ToHexString(xTag)}");

var xRecovered = XChaCha20Poly1305Cipher.Decrypt(xKey, xNonce, xCiphertext, xTag, aad);
Check(xRecovered.AsSpan().SequenceEqual(plaintext), "XC20P round-trip recovers the plaintext");
Console.WriteLine();

// -------------------------------------------------------
// 4. AES Key Wrap (JOSE "A256KW") — wrap a CEK under a KEK
// -------------------------------------------------------
Console.WriteLine("=== AES Key Wrap (A256KW) ===");

// In JWE the message is encrypted once with a random content-encryption
// key (CEK); the CEK itself is then wrapped under each recipient's
// key-encryption key (KEK). Key Wrap has no nonce: it is deterministic by
// design (RFC 3394), which is acceptable because CEKs are random one-time keys.
var kek = RandomNumberGenerator.GetBytes(32); // 32-byte KEK (A256KW)
var cek = RandomNumberGenerator.GetBytes(32); // 32-byte CEK (e.g. for A256GCM)

var wrapped = AesKeyWrap.Wrap(kek, cek);
// The wrapped key is always 8 bytes longer: one extra semiblock of integrity material.
Console.WriteLine($"  CEK:     {cek.Length} bytes");
Console.WriteLine($"  Wrapped: {wrapped.Length} bytes (CEK + 8-byte integrity block)");

var unwrapped = AesKeyWrap.Unwrap(kek, wrapped);
Check(unwrapped.AsSpan().SequenceEqual(cek), "A256KW Unwrap recovers the original CEK");
Console.WriteLine();

// -------------------------------------------------------
// 5. Base64url — the JOSE byte-to-text boundary
// -------------------------------------------------------
Console.WriteLine("=== Base64url (RFC 4648 §5, no padding) ===");

// Every JOSE/JWK field that carries bytes — JWE iv/ciphertext/tag/encrypted_key,
// JWK x/y/d, apu/apv, signatures — is base64url with NO padding. Base64Url is the
// foundation's single source of truth for that encoding, so consumers do not each
// re-implement it and risk a padding/charset divergence.
var encodedCiphertext = Base64Url.Encode(gcmCiphertext);
var encodedTag = Base64Url.Encode(gcmTag);
Console.WriteLine($"  ciphertext (b64url): {encodedCiphertext}");
Console.WriteLine($"  tag        (b64url): {encodedTag}");
Check(!encodedTag.Contains('='), "base64url output carries no '=' padding");

// Decode tolerates input with or without padding and round-trips exactly.
var decodedTag = Base64Url.Decode(encodedTag);
Check(decodedTag.AsSpan().SequenceEqual(gcmTag), "Base64Url.Decode round-trips the tag bytes");
Console.WriteLine();

// -------------------------------------------------------
// 6. Tampering is detected — the authentication guarantee
// -------------------------------------------------------
Console.WriteLine("=== Tamper detection ===");

// Flip a single bit of the GCM ciphertext. An attacker on the wire could do
// exactly this; with plain (unauthenticated) encryption it would silently
// corrupt the plaintext. An AEAD instead refuses to decrypt at all: the tag
// check fails and Decrypt throws CryptographicException BEFORE returning a
// single byte of plaintext. This is the guarantee you buy with the 16 extra
// tag bytes — never ignore or downgrade this exception.
var tampered = (byte[])gcmCiphertext.Clone();
tampered[0] ^= 0x01; // one flipped bit is enough

var tamperDetected = false;
try
{
    AesGcmCipher.Decrypt(gcmKey, gcmNonce, tampered, gcmTag, aad);
}
catch (CryptographicException ex)
{
    tamperDetected = true;
    Console.WriteLine($"  Flipped 1 bit of ciphertext -> CryptographicException: {ex.Message}");
}
Check(tamperDetected, "tampered ciphertext is rejected, no plaintext released");
Console.WriteLine();

Console.WriteLine("Done! All encryption examples completed successfully.");
return 0;

// Prints each expectation; any failure exits non-zero so scripts/CI notice.
static void Check(bool condition, string what)
{
    Console.WriteLine($"  {(condition ? "OK" : "FAILED")}: {what}");
    if (!condition) Environment.Exit(1);
}
