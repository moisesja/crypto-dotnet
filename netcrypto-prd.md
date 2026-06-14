# NetCrypto — Product Requirements Document (PRD)

**Repository:** `crypto-dotnet` · **Package / root namespace:** `NetCrypto`
**Status:** Draft for approval · **Date:** 2026-06-09
**Precedes:** implementation. **Preceded by:** `netcrypto-concept.md` (approved 2026-06-09).
**Source of migrated code:** `github.com/moisesja/net-did`, branch `main` (paths below are relative to that repo).

---

## 0. How to use this document (instructions to implementing agents)

1. Requirements are numbered `FR-*` (functional) and `NFR-*` (non-functional). Each has **Acceptance criteria** that are binary — they pass or fail with no judgment call. Do not consider an FR complete until every criterion passes.
2. Where an FR says **migrate**, the source of truth is the existing file in `net-did`. Behavior parity is mandatory: do not "improve" migrated logic, rename members, change exception types, or alter wire formats unless the FR explicitly says so. The migrated unit tests are the parity oracle.
3. Where an FR says **new**, implement strictly against the cited specification and its test vectors. Never invent test vectors; use the ones cited.
4. Work in phases (§8). Do not begin a phase before the previous phase's gate passes.
5. Anything in §7 (out of scope) must not appear in the deliverable, even as "helpful extras."

---

## 1. Deliverable inventory

| Artifact | Requirement |
|---|---|
| Git repository `crypto-dotnet` | Source-only; no compiled binaries committed (enforced: FR-20) |
| NuGet package `NetCrypto` | Single package; contains managed assembly + native BBS libraries for 5 RIDs |
| Projects | `src/NetCrypto/NetCrypto.csproj`, `tests/NetCrypto.Tests/NetCrypto.Tests.csproj`, `native/zkryptium-ffi/` (Rust crate, moved from net-did) |
| CI | `build.yml` (PR/push), `release.yml` (tag-triggered pack & publish) |
| Docs | `README.md` with spec-conformance appendix; XML doc comments on all public members |
| Examples | `samples/` — standalone runnable console programs covering 100% of the public API (FR-17); the learning path for developers, separate from tests |

### 1.1 Repository layout (exact)

```
crypto-dotnet/
├── src/NetCrypto/
│   ├── NetCrypto.csproj
│   ├── (public types — single root namespace NetCrypto)
│   ├── Native/            (internal FFI layer — namespace NetCrypto.Native)
│   └── runtimes/          (EMPTY in git; populated by CI at pack time; .gitignore'd)
├── tests/NetCrypto.Tests/
├── samples/               (FR-17 — one console project per API area; see layout there)
│   ├── NetCrypto.Samples.Keys/
│   ├── NetCrypto.Samples.Signing/
│   ├── NetCrypto.Samples.Signers/
│   ├── NetCrypto.Samples.Bbs/
│   ├── NetCrypto.Samples.KeyAgreement/
│   ├── NetCrypto.Samples.Hashing/
│   ├── NetCrypto.Samples.EvmSigning/
│   ├── NetCrypto.Samples.Encryption/
│   ├── NetCrypto.Samples.Jwk/
│   └── NetCrypto.Samples.DependencyInjection/
├── native/zkryptium-ffi/  (Cargo.toml, src/lib.rs, README.md — moved verbatim from net-did/native/zkryptium-ffi; target/ gitignored)
├── .github/workflows/build.yml
├── .github/workflows/release.yml
├── Directory.Build.props  (central versioning: $(NetCryptoVersion); nullable enable; TFM net10.0)
├── README.md
├── LICENSE                (copy the license used by net-did/net-cid)
└── .gitignore             (must cover: **/runtimes/**/native/*, native/zkryptium-ffi/target/)
```

### 1.2 Package metadata

- `PackageId`: `NetCrypto`. Root namespace and assembly name: `NetCrypto`.
- TFM: `net10.0`. `Nullable`: enable. `AllowUnsafeBlocks`: only if the FFI layer requires it (it currently does not — `LibraryImport` with spans suffices).
- Description: "Unified cryptographic primitives for the NetCid/NetDid library stack: EdDSA, ECDSA (NIST + secp256k1, incl. recoverable), BLS12-381, BBS selective-disclosure signatures, X25519/ECDH, KDFs, AEADs, hashing (incl. Keccak-256), key model, signing and key-store abstractions, and JWK conversion."

### 1.3 NuGet dependencies (closed list)

`NetCid`, `NSec.Cryptography`, `NBitcoin.Secp256k1`, `Nethermind.Crypto.Bls`, `Microsoft.IdentityModel.Tokens`, `Microsoft.Extensions.DependencyInjection.Abstractions`, `Microsoft.SourceLink.GitHub` (PrivateAssets=All).

**Ruling on `Microsoft.IdentityModel.Tokens`:** retained for v1. `JwkConverter` and `KeyPair.ToPublicJwk()/ToPrivateJwk()` return `Microsoft.IdentityModel.Tokens.JsonWebKey` today; parity wins. Modern versions (8.x) use `System.Text.Json`, so NFR-2 is not violated. Replacing it with a native JWK model is a possible v2 item, not v1.

**Acceptance criteria (AC-1):**
- [ ] `dotnet list src/NetCrypto package` shows exactly the packages above (plus transitive).
- [ ] No reference to `Newtonsoft.Json` appears in the dependency graph (`dotnet list package --include-transitive | grep -i newtonsoft` is empty).
- [ ] `git ls-files | grep -E '\.(dll|so|dylib)$'` returns empty (source-only repo).

### 1.4 Reference implementations (read before implementing)

Two sibling repositories by the same author (same licensing) already implement much of this PRD. Consult them before writing code; for migration FRs they are the source of truth, and for new-primitive FRs they are proven starting points whose core logic and test vectors may be ported.

| Concern | Reference | How to use it |
|---|---|---|
| All Phase-A migrations (FR-1…FR-9) | `github.com/moisesja/net-did` — `src/NetDid.Core/Crypto/`, `Jwk/`, interface files, `native/zkryptium-ffi/`, and `tests/NetDid.Core.Tests/` | **Source of truth.** Move verbatim per the FR rules; tests are the parity oracle |
| A256GCM (FR-13) | `github.com/moisesja/didcomm-dotnet` — `src/DidComm.Core/Crypto/Aead/AesGcmAead.cs` + `tests/.../Aead/AesGcmAeadTests.cs` | Proven BCL-backed wrapper; port logic and IO-contract tests |
| A256CBC-HS512 (FR-14) | same repo — `Crypto/Aead/AesCbcHmacSha512.cs` + tests | Implements RFC 7518 §5.2.2 exactly: key split, AL block, 32-byte truncated tag, `FixedTimeEquals`, tag-before-decrypt. Its test file carries the Appendix B.3 vector verbatim — port both |
| A256KW (FR-15) | same repo — `Crypto/KeyWrap/AesKeyWrap.cs` + tests | RFC 3394 §2.2 implementation with the §4.6 vector in tests; PRD additionally requires the §4.3 vector |
| XC20P (FR-16) | same repo — `Crypto/Aead/XChaCha20Poly1305Aead.cs` + tests | Thin pass-through to NSec `AeadAlgorithm.XChaCha20Poly1305` (handles NSec's combined `ciphertext‖tag` buffer split) |
| Boundary illustration (do NOT port) | same repo — `Crypto/Kdf/Ecdh1PuKdf.cs`, `EcdhEsKdf.cs` | Shows the consumer side: DIDComm composes ECDH-ES/1PU from `ConcatKdf` + raw shared secrets. This stays in didcomm-dotnet (§7); it is the usage NetCrypto's KDF/`DeriveSharedSecret` surface must serve |

**Porting caveats for agents:** the didcomm-dotnet types are `internal` and shaped to its `IAead` interface (instance classes with `Name`/`KeySizeBytes` metadata for JWE-header dispatch). NetCrypto's public API shape is defined by FR-13…FR-16, not by `IAead` — port the algorithm core and the test vectors, not the interface. Keep didcomm-dotnet's input-validation messages' *rigor*, not necessarily their text.

---

## 2. Functional requirements — migration (Phase A)

> Global rule for FR-1 … FR-9: **namespace mapping** is `NetDid.Core` → `NetCrypto`, `NetDid.Core.Crypto` → `NetCrypto`, `NetDid.Core.Crypto.Kdf` → `NetCrypto`, `NetDid.Core.Crypto.Native` → `NetCrypto.Native` (internal), `NetDid.Core.Jwk` → `NetCrypto`. Type names, member names, signatures, exception types, and XML docs are otherwise preserved verbatim except where an FR states a change.

### FR-1 — Key model

Migrate `KeyType` (enum: Ed25519, X25519, P256, P384, Secp256k1, Bls12381G1, Bls12381G2, P521 — preserve member order/values), `KeyTypeExtensions` (`GetMulticodec`, `FromMulticodec`, full 8-entry map to `NetCid.Multicodec` constants), `KeyPair`, `PublicKeyReference`, `StoredKeyInfo`, `EcdsaSignatureFormat` (Der=0, IeeeP1363=1, docs preserved).

**Acceptance criteria:**
- [ ] All six types compile in namespace `NetCrypto` with public surface byte-identical to source (verified by API-surface diff, NFR-1).
- [ ] `MultibasePublicKey` on `KeyPair`/`PublicKeyReference`/`StoredKeyInfo` produces output identical to net-did for the same inputs (parity test: fixed Ed25519 key → expected `z6Mk…` string captured from net-did before migration).
- [ ] Round-trip test per key type: `GetMulticodec` → `FromMulticodec` is identity for all 8 members; `FromMulticodec(unknown)` throws `ArgumentException`.

### FR-2 — Core crypto interfaces

Migrate `ICryptoProvider` (both `Sign`/`Verify` overload pairs, `KeyAgreement`, `DeriveSharedSecret`) and `IKeyGenerator`, with XML docs intact.

**Acceptance criteria:**
- [ ] Interfaces exist in `NetCrypto` with identical member signatures (API-surface diff).
- [ ] XML doc comments preserved (spot-check: `DeriveSharedSecret` remarks still cite RFC 7518 §4.6).

### FR-3 — `DefaultCryptoProvider`

Migrate verbatim, including: Ed25519 (NSec, 32-byte seed private keys), NIST ECDSA P-256/384/521 with DER↔IEEE-P1363 handling (`DSASignatureFormat` mapping), secp256k1 (SHA-256 prehash, 64-byte compact R‖S), BLS12-381 G1/G2 with the existing DSTs (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` and G1 counterpart), X25519 `KeyAgreement` (HKDF-SHA256 wrapper) and `DeriveSharedSecret` (X25519 and **all three** NIST curves P-256/P-384/P-521 — per the source switch in `DefaultCryptoProvider.DeriveSharedSecret`; P-521 is in active use by didcomm-dotnet's ECDH paths), SEC1 point validation/decompression (`EcPointValidator`, BigInteger curve constants).

**Acceptance criteria:**
- [ ] All net-did tests under `tests/NetDid.Core.Tests/Crypto/` covering this class migrate (namespaces re-pointed only) and pass unmodified in assertion content.
- [ ] Cross-format test: P-256 signature produced as DER verifies as DER and fails (returns `false`, no throw) when verified as IeeeP1363, and vice versa.
- [ ] Two-party agreement test per ECDH-capable type (X25519, P-256, P-384, P-521): independently generated pairs derive byte-identical shared secrets from both sides; a non-ECDH key type (e.g. Ed25519) throws `ArgumentException`.
- [ ] Ed25519 sign/verify validated against RFC 8032 §7.1 test vectors (TEST 1–3 minimum: secret key, public key, message, expected signature).
- [ ] No type from NSec/NBitcoin/Nethermind appears in any public signature (NFR-1).

### FR-4 — KDFs

Migrate `ConcatKdf.DeriveKey` (NIST SP 800-56A Concat KDF) verbatim. Additionally (**new, small**): expose `Hkdf` static helper wrapping BCL `System.Security.Cryptography.HKDF` for `Extract`/`Expand`/`DeriveKey` with SHA-256/384/512, so consumers don't reach into the BCL with inconsistent parameter conventions.

**Acceptance criteria:**
- [ ] `ConcatKdf` parity tests migrate and pass.
- [ ] `Hkdf` validated against RFC 5869 Appendix A test case 1 (SHA-256: IKM `0x0b`×22, salt `0x00..0x0c`, info `0xf0..0xf9`, L=42 → expected OKM per RFC) and test case 3 (zero-length salt/info).

### FR-5 — BBS provider with ciphersuite parameter

Migrate `IBbsCryptoProvider`, `DefaultBbsCryptoProvider`, `ZkryptiumNative` (internal), and the Rust crate. Apply exactly these changes (decisions 6 and 8 of the concept doc):

1. Rename user-facing terminology "BBS+" → "BBS" in XML docs, README, and the FFI README (type and member names unchanged).
2. Add `public enum BbsCiphersuite { Bls12381Sha256 = 0 }`.
3. Add to `IBbsCryptoProvider`: `BbsCiphersuite Ciphersuite { get; }` and `bool IsAvailable { get; }`.
4. `DefaultBbsCryptoProvider` gains constructor parameter `BbsCiphersuite ciphersuite = BbsCiphersuite.Bls12381Sha256`; any other value throws `NotSupportedException` naming the unsupported suite.
5. Define `public sealed class BbsUnavailableException : System.Security.Cryptography.CryptographicException`, carrying the original native-load error as `InnerException`. All five BBS operations throw it (instead of the current generic throw) when the native library failed to load. `IsAvailable` returns the probe result and never throws.
6. Expose the BBS signature **`header`** on `IBbsCryptoProvider`/`DefaultBbsCryptoProvider` (issue #2). Add an optional `ReadOnlySpan<byte> header = default` (last parameter) to `Sign`, `Verify`, `DeriveProof`, and `VerifyProof`, threaded into the already-present FFI header arguments (the native `zkryptium-ffi` layer already accepts and consumes it; **no Rust change**). The header is fixed by the signer at sign time and committed by both verification and any derived proof — it lets a consumer bind application data the holder cannot drop or alter (the W3C `bbs-2023` cryptosuite binds its mandatory-disclosure group here). Rename the existing `nonce` parameter on `DeriveProof`/`VerifyProof` to `presentationHeader`: it is the BBS presentation header (`ph`), a value distinct from `header` and chosen by the holder at derive time. Default empty preserves the prior behavior for callers that omit it.

**Acceptance criteria:**
- [ ] BBS round-trip test passes on a platform with the native library: keygen → sign(3 messages) → verify(true) → DeriveProof(reveal indices {0,2}) → VerifyProof(true); tamper any revealed message → VerifyProof(false).
- [ ] Keygen fixture test: deterministic IKM from draft-irtf-cfrg-bbs-signatures-10 BLS12-381-SHA-256 test fixtures produces the fixture's expected SK/PK through the FFI (proves the wrapped zkryptium build matches draft-10; cite the fixture used in the test).
- [ ] Size invariants asserted: SK 32, PK 96, signature 80 bytes.
- [ ] With the native library absent (test by running the managed test assembly with no `runtimes/` payload — CI job, FR-22): `IsAvailable == false`; each of the five operations throws `BbsUnavailableException` with non-null `InnerException`; every non-BBS test in the suite still passes.
- [ ] `new DefaultBbsCryptoProvider((BbsCiphersuite)1)` throws `NotSupportedException`.
- [ ] Header binding (issue #2): `Sign(sk, msgs, header)` + `Verify(pk, sig, msgs, header)` round-trips for a non-empty header, and `Verify` returns `false` for a different header or the default empty header; `DeriveProof(..., presentationHeader, header)` + `VerifyProof(..., presentationHeader, header)` round-trips, and `VerifyProof` returns `false` when the `header` differs from the one bound at derive time (the header is committed by the proof); the `presentationHeader` and `header` are independently committed. The default empty-header behavior is unchanged for callers that omit it.

### FR-6 — Key generation

Migrate `DefaultKeyGenerator` verbatim: `Generate`/`FromPrivateKey`/`FromPublicKey` for all 8 key types (incl. secp256k1 33-byte compressed public keys, BLS G1 48-byte / G2 96-byte compressed), `DeriveX25519FromEd25519`, `DeriveX25519PublicKeyFromEd25519` (birational map, 32-byte input validation with the existing `ArgumentException` message).

**Acceptance criteria:**
- [ ] Migrated tests pass unmodified.
- [ ] Per key type: `Generate(t)` → sign/verify round-trip via `DefaultCryptoProvider` succeeds (BBS types via BLS sign/verify).
- [ ] Ed25519→X25519 derivation: key-pair path and public-only path produce the same X25519 public key for the same Ed25519 input; derived pair performs successful `KeyAgreement` against an independently generated X25519 pair.

### FR-7 — Signing and key-store abstractions

Migrate `ISigner`, `KeyPairSigner`, `KeyStoreSigner`, `IKeyStore` (the original seven members: `GenerateAsync`, `ImportAsync`, `GetInfoAsync`, `SignAsync`, `CreateSignerAsync`, `ListAsync`, `DeleteAsync`) verbatim, including null-argument guards and the HSM-first doc language.

**Key agreement (issue #11, 1.1.0):** `IKeyStore` gains an eighth member —
`DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken)` — the
key-agreement counterpart to `SignAsync`. It performs ECDH against a stored key-agreement private key
and returns the **raw shared secret Z** (no KDF; the caller still owns the Concat-KDF/HKDF step,
consistent with `ICryptoProvider.DeriveSharedSecret`), so a non-extractable (e.g. HSM-bound) key can
participate in ECDH-based decryption (JOSE `ECDH-ES`/`ECDH-1PU`, DIDComm anoncrypt/authcrypt). The
private scalar never leaves the store.

**Acceptance criteria:**
- [ ] Migrated tests (incl. `tests/NetDid.Core.Tests/KeyStore/`) pass unmodified.
- [ ] `KeyPairSigner.SignAsync` output verifies via `ICryptoProvider.Verify` for Ed25519 and P-256.
- [ ] A test-double `IKeyStore` proves `KeyStoreSigner` never reads private key material (signature delegated; only alias + public key held).
- [ ] `IKeyStore.DeriveSharedSecretAsync` returns a Z byte-for-byte identical to `ICryptoProvider.DeriveSharedSecret` for the extractable equivalent, across **X25519, P-256, P-384, P-521**, without exposing the private scalar; a non-ECDH stored key throws `ArgumentException`, an unknown alias throws `KeyNotFoundException`.

### FR-8 — JWK conversion

Migrate `JwkConverter` verbatim (`ToPublicJwk(KeyType, byte[])`, `ToPublicJwk(KeyPair)`, `ToPrivateJwk(KeyPair)`, `ExtractPublicKey(JsonWebKey)`), including base64url handling via `NetCid.Multibase` and SEC1 compressed-point reconstruction. `KeyPair.ToPublicJwk()/ToPrivateJwk()` convenience methods migrate with `KeyPair` (FR-1).

**Acceptance criteria:**
- [ ] Migrated tests under `tests/NetDid.Core.Tests/Jwk/` pass unmodified.
- [ ] Round-trip per supported key type: raw key → JWK → `ExtractPublicKey` → identical bytes + `KeyType`.
- [ ] `ToPrivateJwk` includes `d`; `ToPublicJwk` output contains no private material (assert `D == null`).
- [ ] **On-curve guarantee (invalid-curve defense, RFC 7518 §6.2.2):** `ExtractPublicKey` validates every
  EC point against the stated curve via `EcPointValidator.EnsureOnCurve` **before** returning, throwing
  `CryptographicException` for an off-curve / out-of-range / identity point. The guarantee is stated in the
  method's XML doc and covered by a regression test using a *fabricated, self-consistent* (valid-length but
  off-curve) JWK — so consumers doing `ExtractPublicKey → DeriveSharedSecret` on an untrusted `epk` inherit
  the defense by default.

### FR-9 — Dependency-injection registration

New thin extension (modeled on `NetDid.Extensions.DependencyInjection`): `public static class ServiceCollectionExtensions { public static IServiceCollection AddNetCrypto(this IServiceCollection services); }` registering `ICryptoProvider → DefaultCryptoProvider`, `IBbsCryptoProvider → DefaultBbsCryptoProvider`, `IKeyGenerator → DefaultKeyGenerator` as singletons, all via `TryAdd` so consumer registrations win (this is the Posture-1 swap seam — concept §5).

**Acceptance criteria:**
- [ ] `AddNetCrypto()` then resolve: all three interfaces yield the defaults.
- [ ] Registering a fake `ICryptoProvider` **before** `AddNetCrypto()` → fake wins (TryAdd semantics proven).
- [ ] `IKeyStore` is **not** registered (no default store exists).

---

## 3. Functional requirements — new primitives (Phase B)

### FR-10 — Hashing helpers (SHA-2)

`public static class Hash` exposing `Sha256`, `Sha384`, `Sha512` — each with `byte[] (ReadOnlySpan<byte>)` and a `TryHash`-style span overload — thin wrappers over BCL statics. Driver: SD-JWT disclosure hashing in `credentials-dotnet`.

**Acceptance criteria:**
- [ ] NIST FIPS 180-4 known-answer tests: SHA-256("abc") = `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`; SHA-512("abc") = the FIPS 180-4 documented digest; empty-input digests asserted for all three.

### FR-11 — Keccak-256

`public static class Keccak256` with `byte[] Hash(ReadOnlySpan<byte>)` and a span overload. **This is original Keccak (pre-NIST padding `0x01`), not SHA3-256 (`0x06`).** Implementation: vendored internal Keccak-f[1600] sponge (no new package dependency); cross-validated in tests against a reference implementation added as a **test-only** dependency (e.g. BouncyCastle `KeccakDigest`), which must not appear in `src/`.

**Acceptance criteria:**
- [ ] `Keccak256.Hash("")` = `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
- [ ] `Keccak256.Hash("abc")` = `4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45`.
- [ ] Differential test: 1,000 random inputs (lengths 0–1024, incl. exact multiples of rate 136 and ±1) match the test-only reference implementation.
- [ ] Negative control: output for "" differs from SHA3-256("") (`a7ffc6f8…`), proving correct padding.
- [ ] Ethereum address test: Keccak-256 of an uncompressed secp256k1 public key (64 bytes, no 0x04 prefix), last 20 bytes, matches a documented known key→address pair cited in the test.

### FR-12 — Recoverable secp256k1 ECDSA

`public static class Secp256k1Recoverable` (backed by NBitcoin.Secp256k1's recoverable API):
- `(byte[] Signature64, int RecoveryId) Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> digest32)` — signs a **caller-supplied 32-byte digest** (no internal hashing; did:ethr digests are Keccak-256, computed by the caller). Compact R‖S, low-S normalized; `RecoveryId` ∈ {0,1,2,3}.
- `byte[] RecoverPublicKey(ReadOnlySpan<byte> digest32, ReadOnlySpan<byte> signature64, int recoveryId, bool compressed = false)` — returns 33-byte compressed or 65-byte uncompressed (0x04-prefixed) key.

**Boundary ruling (closes concept open question 2):** NetCrypto returns the raw recovery id. EVM `v`-encoding (`27 + recid`, or EIP-155 `35 + recid + 2·chainId`) is the wallet layer's job and must NOT appear in NetCrypto.

**Acceptance criteria:**
- [ ] Round-trip: random key → `Sign(digest)` → `RecoverPublicKey` equals the true public key (both encodings), 100 random iterations.
- [ ] Recovered-key signature verifies via existing `ICryptoProvider.Verify(KeyType.Secp256k1, …)` path (note: that path hashes internally with SHA-256 — verify against the preimage used to produce the digest accordingly, or assert via NBitcoin directly on the digest; the test must document which).
- [ ] Low-S: for every produced signature, S ≤ n/2 (assert against the curve order constant).
- [ ] Known-vector test: at least one published Ethereum-ecosystem recoverable-signature vector (cite source in test).
- [ ] Wrong recoveryId recovers a different key or throws — never silently the right key.

### FR-13 — AES-256-GCM (A256GCM)

`public static class AesGcmCipher`: `Encrypt(key32, nonce12, plaintext, aad) → (ciphertext, tag16)` and `Decrypt(...)` throwing `CryptographicException` (BCL `AuthenticationTagMismatchException` acceptable) on tag failure. BCL-backed.

**Acceptance criteria:**
- [ ] NIST GCM known-answer vectors pass (cite the CAVP/NIST source per vector; minimum: one 256-bit-key vector with AAD, one without).
- [ ] Tamper tests: flipping any single bit of ciphertext, tag, or AAD → decrypt throws.
- [ ] Key length ≠ 32 or nonce length ≠ 12 → `ArgumentException`.

### FR-14 — AES-256-CBC + HMAC-SHA-512 (A256CBC-HS512)

`public static class AesCbcHmacCipher` implementing the composite AEAD exactly per RFC 7518 §5.2.2 with the 512-bit key split (MAC_KEY = first 32 bytes, ENC_KEY = last 32 bytes), 16-byte IV, AL block = 64-bit big-endian bit-length of AAD, tag = first 32 bytes of HMAC-SHA-512(MAC_KEY, AAD ‖ IV ‖ ciphertext ‖ AL). Constant-time tag comparison (`CryptographicOperations.FixedTimeEquals`). Decrypt: verify tag **before** CBC decryption; tag failure throws without attempting decryption (no padding-oracle path).

**Acceptance criteria:**
- [ ] RFC 7518 **Appendix B.3** test vector reproduced exactly (key K, plaintext P, IV, AAD A → expected E and T as printed in the RFC).
- [ ] Tamper tests as in FR-13.
- [ ] Code-level assertion (test or analyzer) that tag verification precedes decryption and uses `FixedTimeEquals`.

### FR-15 — AES Key Wrap (A256KW)

`public static class AesKeyWrap`: `Wrap(kek32, keyData)` / `Unwrap(kek32, wrapped)` per RFC 3394 (default IV `0xA6A6A6A6A6A6A6A6`, 6·n rounds). Key data must be a multiple of 8 bytes, ≥ 16; violations → `ArgumentException`. Unwrap integrity failure → `CryptographicException`.

**Acceptance criteria:**
- [ ] RFC 3394 §4 vectors: at minimum §4.3 (wrap 128-bit key data with 256-bit KEK) and §4.6 (wrap 256-bit key data with 256-bit KEK) reproduce the RFC's printed outputs exactly.
- [ ] Round-trip with random KEK/key-data (sizes 16/24/32) is identity.
- [ ] Any single-bit corruption of wrapped output → `Unwrap` throws.

### FR-16 — XChaCha20-Poly1305 (XC20P)

**Revised from "deferred" (closes concept open question 1 the other way):** inspection of `didcomm-dotnet` proved NSec — already a NetCrypto dependency — exposes `AeadAlgorithm.XChaCha20Poly1305`, so no new dependency is required and didcomm-dotnet already relies on XC20P in production paths. In scope for v1.

`public static class XChaCha20Poly1305Cipher`: `Encrypt(key32, nonce24, plaintext, aad) → (ciphertext, tag16)` / `Decrypt(...)` — same shape as FR-13. NSec-backed (reference: §1.4); the implementation splits NSec's combined `ciphertext‖tag` output to keep the (ciphertext, tag) contract uniform with the other AEADs. Spec: draft-irtf-cfrg-xchacha-03 (XChaCha20-Poly1305 as used by libsodium/JOSE `XC20P`).

**Acceptance criteria:**
- [ ] draft-irtf-cfrg-xchacha-03 Appendix A AEAD test vector reproduced exactly (plaintext, AAD, key, nonce → expected ciphertext and tag as printed in the draft).
- [ ] Tamper tests as in FR-13 (ciphertext, tag, and AAD bit-flips each throw on decrypt).
- [ ] Key length ≠ 32 or nonce length ≠ 24 → `ArgumentException`.
- [ ] Round-trip property test (random key/nonce/AAD, plaintext lengths 0–4096) is identity.

### FR-16b — AEAD size metadata & base64url codec (1.1.0 ergonomics, issue #12)

Two shared-primitive ergonomics gaps every JOSE/DIDComm consumer otherwise re-implements locally.

**G5 — unified AEAD size metadata.** Each content-encryption cipher type exposes its key/nonce/tag
sizes as `public const int` so a JOSE builder can allocate the CEK and IV/nonce **before** calling
`Encrypt` and validate against the source of truth instead of a hard-coded table:
`AesGcmCipher` (`KeySizeBytes` 32, `NonceSizeBytes` 12, `TagSizeBytes` 16), `AesCbcHmacCipher`
(`KeySizeBytes` 64, `IvSizeBytes` 16, `TagSizeBytes` 32), `XChaCha20Poly1305Cipher`
(`KeySizeBytes` 32, `NonceSizeBytes` 24, `TagSizeBytes` 16). The IV/nonce name follows each cipher's
own parameter (CBC has an IV; GCM/XChaCha have a nonce).

**G4 — base64url codec.** `public static class Base64Url` provides `Encode(ReadOnlySpan<byte>) → string`
(RFC 4648 §5, no `=` padding) and `Decode(ReadOnlySpan<char>) → byte[]` (tolerates optional padding),
a thin wrapper over the BCL `System.Buffers.Text.Base64Url`. This is the single source of truth for the
JOSE/JWK byte boundary (headers, signatures, JWE `iv`/`ciphertext`/`tag`/`encrypted_key`, JWK
`x`/`y`/`d`, `apu`/`apv`). Placement note: base64url arguably belongs in a future JOSE-enveloping module;
it lands in the foundation package because that module does not exist yet.

**Acceptance criteria:**
- [ ] Each AEAD cipher type exposes its key/nonce/tag sizes as public constants, asserted against the
  bytes the cipher actually accepts and produces (a key one byte short of `KeySizeBytes` is rejected).
- [ ] `Base64Url` round-trips the RFC 7515 Appendix A.1 JOSE vector, emits no `=` padding, uses the
  URL-safe alphabet (`-`/`_`), tolerates padded input on decode, and throws `FormatException` on invalid
  input — including **whitespace** and any non-alphabet character (strict; the bare BCL decoder would
  silently strip whitespace, which a canonical JOSE primitive must not).

### FR-17 — Developer examples (`samples/`)

Every public API is exemplified by simple, runnable programs under `samples/`, following the `net-did` `samples/` convention. This is the developer learning path: a developer must be able to learn correct usage of any public API by reading samples alone, **never** by reading unit or integration tests.

**Structure and content rules:**

1. Ten standalone console projects, one per API area, named as in §1.1 (`NetCrypto.Samples.{Area}`). Mapping:
   | Project | Demonstrates |
   |---|---|
   | `Keys` | `KeyType`, `IKeyGenerator`/`DefaultKeyGenerator` (generate, from-private, from-public), `KeyPair`, `PublicKeyReference`, `MultibasePublicKey`, Ed25519→X25519 derivation (both forms) |
   | `Signing` | `ICryptoProvider`/`DefaultCryptoProvider` sign/verify per key type; `EcdsaSignatureFormat` — same P-256 key producing DER and IEEE-P1363, and why JOSE needs the latter |
   | `Signers` | `ISigner`, `KeyPairSigner`; `IKeyStore` implemented as a minimal in-memory store *inside the sample*, `KeyStoreSigner`, `StoredKeyInfo`, `CreateSignerAsync` — illustrating the "private key never leaves the store" pattern |
   | `Bbs` | `IBbsCryptoProvider`, `BbsCiphersuite`, multi-message sign → verify → `DeriveProof` with selective disclosure → `VerifyProof`; checking `IsAvailable` and catching `BbsUnavailableException` as the graceful-degradation pattern |
   | `KeyAgreement` | X25519 `KeyAgreement`, raw `DeriveSharedSecret` (X25519 + P-256), feeding `ConcatKdf` and `Hkdf` — two parties deriving the same key |
   | `Hashing` | `Hash` (SHA-256/384/512), `Keccak256`, including a comment-level warning that Keccak-256 ≠ SHA3-256 |
   | `EvmSigning` | `Secp256k1Recoverable` sign over a Keccak-256 digest, `RecoverPublicKey`, deriving an Ethereum address from the recovered key (usage illustration only — the `v`-encoding boundary note from FR-12 repeated in comments) |
   | `Encryption` | `AesGcmCipher`, `AesCbcHmacCipher`, `XChaCha20Poly1305Cipher`, `AesKeyWrap` — encrypt/decrypt round-trips with AAD, plus a deliberate tamper showing the authentication failure |
   | `Jwk` | `JwkConverter` and `KeyPair.ToPublicJwk()/ToPrivateJwk()` round-trips; printing the JWK JSON |
   | `DependencyInjection` | `AddNetCrypto()`, resolving the interfaces, and overriding a default registration (the Posture-1 swap seam) |
2. Each sample: a single `Program.cs` (top-level statements), target ≤ ~150 lines, every step commented in plain language explaining *why*, not just *what*; `Console.WriteLine` output showing the result of each step; exit code 0 on success and non-zero on any failed expectation.
3. Samples reference the `NetCrypto` project (ProjectReference in the solution) and **no** test framework (`xunit`, `NUnit`, `MSTest`, `FluentAssertions` are forbidden in `samples/`).
4. `samples/README.md` indexes the ten projects with a one-line description and a "start here" order.
5. Samples are part of the solution and CI: built with `-warnaserror` and **executed** (each must exit 0) in `build.yml`; the BBS sample must exit 0 both with the native library present (full demo) and absent (prints the `IsAvailable == false` path and skips gracefully) — it demonstrates the supported BBS-absent mode rather than failing in it.

**Acceptance criteria:**
- [ ] All ten projects exist, build with `-warnaserror`, and run to exit 0 in CI on all three OS legs.
- [ ] **Coverage check (mechanical):** a CI script reflects over the `NetCrypto` public API surface and verifies every public type name and every public method/property name appears in at least one `samples/**/*.cs` file; the script's exemption list is empty (or each entry carries a written justification in the script, reviewed by the maintainer). CI fails on uncovered members — this is what makes "every public API is exemplified" agent-verifiable.
- [ ] `grep -rE "xunit|NUnit|MSTest|FluentAssertions" samples/` returns empty.
- [ ] `samples/README.md` exists and indexes exactly the ten projects.
- [ ] The BBS sample run in the no-native CI leg (FR-20) exits 0 and prints the unavailable-mode path.

---

## 4. Non-functional requirements

### NFR-1 — Public API hygiene (backend isolation)

No type from `NSec.*`, `NBitcoin.*`, `Nethermind.*`, or `NetCrypto.Native` in any public signature. (`Microsoft.IdentityModel.Tokens.JsonWebKey` and `NetCid` types are the sanctioned exceptions.)

**Acceptance criteria:**
- [ ] Public API surface is captured with `Microsoft.CodeAnalysis.PublicApiAnalyzers` (`PublicAPI.Shipped.txt` committed); CI fails on undeclared surface changes.
- [ ] A test reflects over the public surface and asserts no parameter/return/property type originates from the forbidden assemblies.

### NFR-2 — Serialization
Any JSON handling uses `System.Text.Json` (or `Microsoft.IdentityModel.Tokens` 8.x). **AC:** dependency-graph check from AC-1.

### NFR-3 — Input validation
Every public method validates lengths/nulls and throws `ArgumentException`/`ArgumentNullException` with the parameter name before any crypto operation. **AC:** per-primitive negative tests exist (each FR above includes them); no public method can be made to throw `IndexOutOfRangeException`/`NullReferenceException` from bad input (fuzz-lite test: null/empty/oversized inputs across the surface). A wrong-length raw key/scalar handed to a backend (NSec, Nethermind BLS, platform EC import) must surface as a **parameter-named `ArgumentException`**, never a leaked backend type (`System.FormatException`, `Nethermind.Crypto.Bls+BlsException`, or a platform `CryptographicException`); the fuzz-lite suite carries **no** "known deviation" allow-list, and any non-contract exception fails it rather than being pinned.

### NFR-4 — Determinism and thread safety
All `Default*` providers and static classes are stateless/thread-safe. **AC:** a parallel test (≥ 8 threads × 100 ops on one shared provider instance, mixed key types) completes without error and with valid outputs.

### NFR-5 — XML documentation
`GenerateDocumentationFile=true`; CS1591 (missing XML doc) treated as error. **AC:** build passes with that setting.

---

## 5. CI, native build, and packaging (Phase C)

### FR-20 — `build.yml` (every PR and push to main)

Matrix: `ubuntu-latest`, `macos-latest`, `windows-latest`. Steps per leg: install Rust (pinned toolchain version, committed in `rust-toolchain.toml`); `cargo build --release` for the **host** target; copy the binary to the test output's native path; `dotnet build -warnaserror`; `dotnet test`.

**Acceptance criteria:**
- [ ] All three legs green, including BBS tests (proving the FFI works on all three OS families).
- [ ] All ten `samples/` projects are built and executed in each leg; each exits 0 (FR-17).
- [ ] A fourth leg runs `dotnet test` **without** building the native library, filtered to exclude BBS-required tests but **including** the FR-5 unavailability tests — proving supported BBS-absent mode (concept decision 8). The same leg runs the BBS sample, which must exit 0 via its unavailable-mode path.

### FR-21 — `release.yml` (on tag `v*`)

Builds all five RIDs: `linux-x64` and `linux-arm64` on ubuntu (arm64 via `cross` or an arm64 runner); `osx-arm64` and `osx-x64` on a macOS runner (`x86_64-apple-darwin` target added); `win-x64` natively on windows. Artifacts are assembled into `src/NetCrypto/runtimes/{rid}/native/` with the exact filenames .NET probes for (`libzkryptium_ffi.dylib` / `libzkryptium_ffi.so` / `zkryptium_ffi.dll`); then `dotnet pack`; SHA-256 checksums of all five binaries and the `.nupkg` are published as release assets; push to NuGet gated on all prior jobs.

**Acceptance criteria:**
- [ ] A dry-run tag produces a `.nupkg`; `unzip -l` shows all five `runtimes/{rid}/native/` entries with correct filenames.
- [ ] Checksum file lists six entries (5 binaries + nupkg).
- [ ] Repo after release contains no new binaries (`git status` clean; `.gitignore` rule verified).

### FR-22 — Per-RID smoke test

Post-pack jobs on `ubuntu-latest`, `macos-latest` (arm64), `windows-latest` install the freshly packed `.nupkg` from a local feed into a minimal console project that runs one BBS sign/verify round-trip and prints `IsAvailable`.

**Acceptance criteria:**
- [ ] Smoke test exits 0 with `IsAvailable == true` on all three runner platforms (covers linux-x64, osx-arm64, win-x64 natively).
- [ ] If GitHub-hosted arm64 Linux runners (`ubuntu-*-arm`) and/or Intel macOS runners are available to the repository, the smoke matrix extends to linux-arm64 / osx-x64 on them; any RID not smoke-executed is covered by the FR-21 binary-presence + checksum check, with the limitation documented in the workflow file.

---

## 6. Downstream adoption — explicitly out of scope, tracked separately

Changes to any other repository are **not** part of this PRD and must not be made by agents implementing it. Specifically:

- **`net-did`** consuming NetCrypto (deleting its `Crypto/`, `Jwk/`, interfaces, FFI, and `runtimes/`; re-pointing namespaces) is a separate, future work item with its own tracking.
- **`didcomm-dotnet`** adopting NetCrypto (deleting its internal A256GCM / A256CBC-HS512 / A256KW / XC20P copies and re-pointing its `ConcatKdf` imports) is likewise separate, planned after net-did's adoption.

This PRD's scope ends at a published, fully verified `NetCrypto` package. Both sibling repos serve here only as **read-only references** (§1.4): migration sources, parity-test sources, and proven implementations to port from. Copying their code and tests *into* `crypto-dotnet` is in scope; modifying them is not.

## 7. Out of scope (must NOT appear)

CBOR APIs; Data Integrity / `eddsa-jcs-2022` proof engine; JCS canonicalizer; JOSE/JWS/JWE/SD-JWT envelope construction; ECDH-1PU assembly helpers; EVM `v`-encoding, RLP, or transaction types; concrete HSM/KMS key stores; any per-`KeyType` provider registry (Posture 1 — registry is a documented future path only); **any change to the `net-did` or `didcomm-dotnet` repositories** (§6 — tracked separately); any project/product branding in code, docs, or package metadata.

---

## 8. Phases and gates

| Phase | Contents | Gate |
|---|---|---|
| A — Scaffold + migration | §1, FR-1…FR-9 | All Phase-A ACs + NFR suite green on host platform |
| B — New primitives + examples | FR-10…FR-17 | All spec-vector tests green; all ten samples run to exit 0; API coverage script passes |
| C — CI + packaging | FR-20…FR-22, NFR-1 analyzer wiring | Dry-run release produces verified 5-RID package; samples executed in all CI legs |

Definition of done = every checkbox in this document checked, plus: README written with the algorithm/spec conformance table (mirroring concept §2, marking BBS as draft-10-pinned) and linking to `samples/README.md` as the primary usage documentation, `PublicAPI.Shipped.txt` reviewed by the maintainer, and the concept-to-FR traceability table verified (every row implemented; no unmapped capability).

---

## Appendix — Concept-to-FR traceability

Normative completeness check for concept §8 package-level criterion 6 ("surface complete for downstream needs"): every concept capability row maps to at least one FR. An unmapped row, or an FR-less driver, is a PRD defect.

| Concept ref | Capability | Driver / consumer | FR(s) |
|---|---|---|---|
| §2.1 | Signatures — EdDSA, NIST ECDSA (both formats), secp256k1, BLS12-381 | net-did, dataproofs-dotnet, credentials-dotnet | FR-2, FR-3 |
| §2.1 | BBS sign / verify / proof-gen / proof-verify | credentials-dotnet (`bbs-2023`) | FR-5 |
| §2.2 | Recoverable secp256k1 over caller digest | did:ethr, EVM payments (wallet layer) | FR-12 |
| §2.3 | X25519 agreement; raw ECDH Z (X25519, P-256, P-384, P-521); Concat KDF; HKDF | didcomm-dotnet (ECDH-ES / ECDH-1PU composition) | FR-3, FR-4 |
| §2.4 | SHA-2 helpers; Keccak-256 | credentials-dotnet (SD-JWT); did:ethr | FR-10, FR-11 |
| §2.5 | A256GCM; A256CBC-HS512; A256KW; XC20P | didcomm-dotnet (DIDComm v2.1 suites) | FR-13, FR-14, FR-15, FR-16 |
| §2.6 | Key model, `KeyType`⇄multicodec, generation, Ed25519→X25519 | all consumers | FR-1, FR-6 |
| §2.6 | `ISigner` / `KeyPairSigner` / `KeyStoreSigner` / `IKeyStore` | all signing consumers | FR-7 |
| §2.7 | JWK ⇄ raw key conversion | net-did, dataproofs-dotnet, didcomm-dotnet | FR-8 |
| §2.8 | DI registration (`AddNetCrypto`, TryAdd seam) | all consumers | FR-9 |
| §5 | Ciphersuite parameterization; Posture-1 swap seam; API hygiene | architecture decisions 6, 10 | FR-5, FR-9, NFR-1 |
| §6 | 5-RID native distribution; BBS-absent supported mode | concept decisions 7, 8 | FR-20, FR-21, FR-22, FR-5 |
| §2 (cross-cutting) | Developer examples for the entire public surface | maintainer requirement | FR-17 |

## Appendix — Test-vector source index

| Primitive | Vector source |
|---|---|
| Ed25519 | RFC 8032 §7.1 (TEST 1–3) |
| HKDF | RFC 5869 Appendix A (cases 1, 3) |
| SHA-2 | FIPS 180-4 known answers ("abc", "") |
| Keccak-256 | Known answers in FR-11 + differential vs. test-only reference |
| A256CBC-HS512 | RFC 7518 Appendix B.3 |
| AES Key Wrap | RFC 3394 §4.3, §4.6 |
| AES-GCM | NIST CAVP GCM vectors (cite file/index per test) |
| XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha-03 Appendix A AEAD vector |
| BBS | draft-irtf-cfrg-bbs-signatures-10 fixtures (BLS12-381-SHA-256), keygen minimum |
| Recoverable secp256k1 | Published Ethereum-ecosystem vector (cited in test) + 100× round-trip property |
| Multibase/Multikey parity | Captured net-did outputs (pre-migration golden values) |
