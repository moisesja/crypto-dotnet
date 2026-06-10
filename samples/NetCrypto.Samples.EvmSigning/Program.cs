using NetCrypto;

// ============================================================
// NetCrypto Samples — EVM Signing (recoverable secp256k1)
// ============================================================
//
// Ethereum signatures are "recoverable": the signature carries enough
// information to RECOVER the signer's public key — and therefore the
// signer's address — from the signature and digest alone. That is why
// Ethereum transactions do not include the sender's public key.
//
// BOUNDARY (PRD FR-12): NetCrypto returns the RAW recovery id (0–3).
// EVM `v`-encoding — legacy `v = 27 + recid`, or EIP-155
// `v = 35 + recid + 2·chainId` — is the WALLET layer's job and is
// deliberately absent from this library.

// -------------------------------------------------------
// 1. The signing key
// -------------------------------------------------------
Console.WriteLine("=== The signing key ===");

// We use the key documented in the EIP-155 specification example
// (private key 0x46…46 → address 0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f)
// so every value below is reproducible and checkable against the spec.
// In production, NEVER hard-code a private key — generate or load one.
var privateKey = new byte[32];
Array.Fill(privateKey, (byte)0x46);

// FromPrivateKey validates the scalar and derives the public key, giving us
// an independent reference to compare the recovered key against later.
var keyGen = new DefaultKeyGenerator();
var key = keyGen.FromPrivateKey(KeyType.Secp256k1, privateKey);
Console.WriteLine($"  Compressed public key: {Convert.ToHexString(key.PublicKey)}");
Console.WriteLine();

// -------------------------------------------------------
// 2. Hash the message — the caller computes the digest
// -------------------------------------------------------
Console.WriteLine("=== Keccak-256 digest ===");

// Secp256k1Recoverable.Sign performs NO hashing: you hand it a 32-byte
// digest and it signs exactly those bytes. Ethereum hashes with Keccak-256
// (the ORIGINAL Keccak, not NIST SHA3-256 — different padding, different
// digests), so we compute that digest ourselves first.
// Note: real wallets frame messages first (e.g. personal_sign prepends
// "\x19Ethereum Signed Message:\n" + length); that framing is wallet-layer
// policy too, so this sample signs the raw message bytes.
var message = "Pay 1 wei to Alice"u8.ToArray();
var digest = Keccak256.Hash(message);
Console.WriteLine($"  Message: \"Pay 1 wei to Alice\"");
Console.WriteLine($"  Digest:  {Convert.ToHexString(digest)}");
Console.WriteLine();

// -------------------------------------------------------
// 3. Sign — compact signature + RAW recovery id
// -------------------------------------------------------
Console.WriteLine("=== Secp256k1Recoverable.Sign ===");

// The result is the 64-byte compact signature (R‖S, low-S normalized,
// deterministic per RFC 6979 — same key + digest always gives the same
// signature) plus the recovery id: which of the candidate curve points R
// could come from. Without it, up to four keys could explain the signature.
var (signature, recoveryId) = Secp256k1Recoverable.Sign(privateKey, digest);
Console.WriteLine($"  Signature (R‖S): {Convert.ToHexString(signature)}");
Console.WriteLine($"  Recovery id:     {recoveryId}  <- raw, NOT an EVM 'v' value");
// To submit this on-chain a wallet would now compute v itself:
//   legacy:  v = 27 + recoveryId
//   EIP-155: v = 35 + recoveryId + 2 * chainId
// NetCrypto deliberately does neither (FR-12 boundary).
Check(signature.Length == 64, "compact signature is 64 bytes");
Check(recoveryId is >= 0 and <= 3, "recovery id is in 0..3");
Console.WriteLine();

// -------------------------------------------------------
// 4. Recover the public key from the signature
// -------------------------------------------------------
Console.WriteLine("=== RecoverPublicKey ===");

// A verifier holding only (digest, signature, recoveryId) — exactly what an
// Ethereum node sees — can reconstruct the signer's public key. Both SEC 1
// encodings are available; pick whichever your protocol expects.
var uncompressed = Secp256k1Recoverable.RecoverPublicKey(digest, signature, recoveryId);
var compressed = Secp256k1Recoverable.RecoverPublicKey(digest, signature, recoveryId, compressed: true);
Console.WriteLine($"  Uncompressed ({uncompressed.Length} bytes): {Convert.ToHexString(uncompressed)}");
Console.WriteLine($"  Compressed   ({compressed.Length} bytes): {Convert.ToHexString(compressed)}");
Check(uncompressed.Length == 65 && uncompressed[0] == 0x04, "uncompressed key is 65 bytes with 0x04 prefix");
Check(compressed.AsSpan().SequenceEqual(key.PublicKey), "recovered key matches the true public key");
Console.WriteLine();

// -------------------------------------------------------
// 5. Derive the Ethereum address (usage illustration only)
// -------------------------------------------------------
Console.WriteLine("=== Ethereum address from the recovered key ===");

// An Ethereum address is Keccak-256 over the 64-byte public key point
// (X‖Y — i.e. the uncompressed encoding WITHOUT its 0x04 prefix), keeping
// only the last 20 bytes. This is shown to complete the picture; address
// rules (and EIP-55 checksum casing) belong to the wallet layer.
var addressBytes = Keccak256.Hash(uncompressed.AsSpan(1))[^20..];
var address = "0x" + Convert.ToHexStringLower(addressBytes);
Console.WriteLine($"  Address: {address}");
// The EIP-155 spec documents this exact key → address pair, so a mismatch
// here would mean the sign/recover/hash chain above is broken.
Check(address == "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f", "address matches the EIP-155 documented value");
Console.WriteLine();

// -------------------------------------------------------
// 6. Why the recovery id matters
// -------------------------------------------------------
Console.WriteLine("=== Wrong recovery id ===");

// The recovery id selects between the candidate keys; with the wrong id you
// get a DIFFERENT (but valid-looking) key — or an exception — never silently
// the right one. This is why wallets must round-trip v <-> recid correctly.
try
{
    var wrong = Secp256k1Recoverable.RecoverPublicKey(digest, signature, recoveryId ^ 1, compressed: true);
    Console.WriteLine($"  recid {recoveryId ^ 1} recovers: {Convert.ToHexString(wrong)}");
    Check(!wrong.AsSpan().SequenceEqual(key.PublicKey), "wrong recovery id yields a different key");
}
catch (Exception ex)
{
    // Equally acceptable: some (digest, signature, recid) combinations have
    // no recoverable point at all, and recovery throws instead.
    Console.WriteLine($"  recid {recoveryId ^ 1} throws: {ex.GetType().Name}");
}
Console.WriteLine();

Console.WriteLine("Done! All EVM signing examples completed successfully.");
return 0;

// Prints each expectation; any failure exits non-zero so scripts/CI notice.
static void Check(bool condition, string what)
{
    Console.WriteLine($"  {(condition ? "OK" : "FAILED")}: {what}");
    if (!condition) Environment.Exit(1);
}
