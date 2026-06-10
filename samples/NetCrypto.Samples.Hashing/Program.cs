using NetCrypto;

// ============================================================
// NetCrypto Samples — Hashing (SHA-2 and Keccak-256)
// ============================================================
//
// `Hash` wraps the SHA-2 family (FIPS 180-4). `Keccak256` is the ORIGINAL
// Keccak as used by Ethereum. Both are stateless static classes — no setup,
// no disposal, safe to call from any thread.

// "abc" is THE classic FIPS 180-4 test vector; every SHA-2 spec and test
// suite publishes its digests, so matching them proves we wired the right
// algorithm (and not, say, SHA-1 or a truncated variant).
var abc = "abc"u8.ToArray();

// -------------------------------------------------------
// 1. SHA-256 — the workhorse (32-byte digest)
// -------------------------------------------------------
Console.WriteLine("=== SHA-256 ===");

// One-shot API: pass bytes, get a fresh digest array back. Use this form
// when you simply need the digest and don't care about allocations.
var sha256 = Hash.Sha256(abc);

Console.WriteLine($"  SHA-256(\"abc\") = {Convert.ToHexStringLower(sha256)}");
// Sanity check against the digest documented in FIPS 180-4. If this ever
// fails, the build is linking the wrong primitive — fail loudly.
Check(Convert.ToHexStringLower(sha256) ==
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "SHA-256(\"abc\") matches the FIPS 180-4 documented value");
Console.WriteLine();

// -------------------------------------------------------
// 2. SHA-384 and SHA-512 — longer digests, same API shape
// -------------------------------------------------------
Console.WriteLine("=== SHA-384 / SHA-512 ===");

// Pick the width your protocol demands (e.g. ES384 needs SHA-384,
// ES512/EdDSA contexts often need SHA-512). The API is identical; only the
// digest length changes: 48 bytes for SHA-384, 64 for SHA-512.
var sha384 = Hash.Sha384(abc);
var sha512 = Hash.Sha512(abc);

Console.WriteLine($"  SHA-384(\"abc\") = {Convert.ToHexStringLower(sha384)}");
Console.WriteLine($"  SHA-512(\"abc\") = {Convert.ToHexStringLower(sha512)}");
Check(Convert.ToHexStringLower(sha384) ==
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" +
    "8086072ba1e7cc2358baeca134c825a7",
    "SHA-384(\"abc\") matches the FIPS 180-4 documented value (48 bytes)");
Check(Convert.ToHexStringLower(sha512) ==
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "SHA-512(\"abc\") matches the FIPS 180-4 documented value (64 bytes)");
Console.WriteLine();

// -------------------------------------------------------
// 3. Try* span overloads — hashing without heap allocation
// -------------------------------------------------------
Console.WriteLine("=== TrySha256 into a stackalloc'd buffer ===");

// In hot paths (hashing thousands of disclosures, hash chains, etc.) the
// byte[] returned by Sha256 becomes GC pressure. The Try* overloads write
// into a caller-owned buffer instead — here a 32-byte buffer on the stack,
// so the whole operation is allocation-free.
Span<byte> digestBuffer = stackalloc byte[32];
var wrote = Hash.TrySha256(abc, digestBuffer, out var written);

Console.WriteLine($"  TrySha256 -> {wrote}, wrote {written} bytes");
Console.WriteLine($"  digest          = {Convert.ToHexStringLower(digestBuffer)}");
Check(wrote && written == 32, "TrySha256 fills a 32-byte buffer");
Check(digestBuffer.SequenceEqual(sha256), "span overload produces the same digest as the array overload");

// Try* returns false (writing nothing) when the buffer is too small — it
// never throws, so you can size buffers defensively and branch on the bool.
Span<byte> tooSmall = stackalloc byte[16];
Check(!Hash.TrySha256(abc, tooSmall, out _), "TrySha256 refuses a 16-byte buffer instead of throwing");
Console.WriteLine();

// -------------------------------------------------------
// 4. Keccak-256 — Ethereum's hash. WARNING: NOT SHA3-256!
// -------------------------------------------------------
Console.WriteLine("=== Keccak-256 (original Keccak, NOT SHA3-256) ===");

// !!! WARNING — Keccak-256 != SHA3-256 !!!
// Original Keccak (this class) and NIST FIPS 202 SHA3-256 share the same
// sponge but use DIFFERENT PADDING: Keccak pads with 0x01, SHA-3 adds
// domain-separation bits and pads with 0x06. Result: they disagree on
// EVERY input. Ethereum standardized on original Keccak before FIPS 202
// was finalized, so for Ethereum addresses, Solidity keccak256(), and
// did:ethr you MUST use this class — a SHA3-256 routine will silently
// produce wrong (and unrecoverable) hashes. The empty-string digests
// below make the mismatch obvious at a glance.
var keccakEmpty = Keccak256.Hash([]);

Console.WriteLine($"  Keccak-256(\"\") = {Convert.ToHexStringLower(keccakEmpty)}");
Console.WriteLine("  SHA3-256(\"\")   = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
Console.WriteLine("                   (FIPS 202 documented value — a completely different digest)");
Check(Convert.ToHexStringLower(keccakEmpty) ==
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    "Keccak-256(\"\") matches the well-known original-Keccak value");
Check(Convert.ToHexStringLower(keccakEmpty) !=
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "Keccak-256(\"\") differs from SHA3-256(\"\") — different padding, different hash");

// A non-empty vector too: keccak256("abc") as Solidity/web3 would compute it.
var keccakAbc = Keccak256.Hash(abc);
Console.WriteLine($"  Keccak-256(\"abc\") = {Convert.ToHexStringLower(keccakAbc)}");
Check(Convert.ToHexStringLower(keccakAbc) ==
    "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    "Keccak-256(\"abc\") matches the Ethereum-ecosystem value");
Console.WriteLine();

// -------------------------------------------------------
// 5. Keccak256.TryHash — same allocation-free pattern
// -------------------------------------------------------
Console.WriteLine("=== Keccak256.TryHash into a stackalloc'd buffer ===");

// Identical contract to Hash.TrySha256: writes 32 bytes if the buffer is
// big enough, returns false (no partial writes) otherwise. Useful when
// hashing per-transaction in tight loops, e.g. computing Ethereum tx ids.
Span<byte> keccakBuffer = stackalloc byte[32];
var keccakWrote = Keccak256.TryHash(abc, keccakBuffer, out var keccakWritten);

Console.WriteLine($"  TryHash -> {keccakWrote}, wrote {keccakWritten} bytes");
Check(keccakWrote && keccakWritten == 32, "TryHash fills a 32-byte buffer");
Check(keccakBuffer.SequenceEqual(keccakAbc), "TryHash matches the array overload");
Check(!Keccak256.TryHash(abc, tooSmall, out _), "TryHash refuses a 16-byte buffer instead of throwing");
Console.WriteLine();

Console.WriteLine("Done! All hashing examples completed successfully.");
return 0;

// Tiny expectation helper: print each result, and abort with a non-zero
// exit code on the first failure so CI catches regressions immediately.
static void Check(bool condition, string what)
{
    Console.WriteLine($"  [{(condition ? "ok" : "FAILED")}] {what}");
    if (!condition)
        Environment.Exit(1);
}
