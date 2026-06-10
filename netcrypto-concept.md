# NetCrypto — Concept Document

**Repository:** `crypto-dotnet` · **Package / namespace:** `NetCrypto`
**Status:** Concept draft for review (precedes PRD)
**Date:** 2026-06-09
**Basis:** Full code audit of `net-did` (`src/NetDid.Core/Crypto/`, `Jwk/`, `native/zkryptium-ffi/`) plus the architectural decisions recorded in `architectural-path.md`.

> **How to read this document.** This is the concept stage: it states *what* the library is, *why*, and *within which boundaries* — not API signatures or implementation detail. Every requirement here traces either to code that exists in `net-did` today (marked **migrates**) or to a named downstream consumer (marked **new**, with the consumer identified). §9 is the decision record; §10 holds what remains open.

---

## 1. Purpose

NetCrypto is the single home for every cryptographic primitive in the library stack, behind stable interfaces, so that no domain library ever binds directly to a specific crypto implementation (NSec, NBitcoin.Secp256k1, Nethermind.Crypto.Bls, the zkryptium FFI, or the .NET base class library).

Today these primitives live inside `net-did`, which forces an inversion: future libraries that need signing or key handling — `dataproofs-dotnet`, `credentials-dotnet`, `didcomm-dotnet` — would have to depend on the *DID* library to get *crypto*. Extracting the primitives into a foundation package restores the intended layering:

```
                net-wallet-sdk
   ┌──────────┬──────┴───────┬─────────────┐
credentials-dotnet  zcap-dotnet  didcomm-dotnet
   └──────────┴──────┬───────┴─────────────┘
              dataproofs-dotnet        net-did
                     └────────┬───────────┘
                          NetCrypto
                              │
                           net-cid
```

(Layering shown top-down by dependency; arrows omitted — every box depends on the boxes below it on its path.)

This is predominantly a **relocation, not a rewrite**: the primitives in `net-did` already sit behind interfaces (`ICryptoProvider`, `IBbsCryptoProvider`, `IKeyGenerator`, `ISigner`) with a single default implementation each.

## 2. Capabilities

### 2.1 Signatures — migrates

| Scheme | Backend today | Specification |
|---|---|---|
| EdDSA (Ed25519) | NSec | RFC 8032 |
| ECDSA P-256 / P-384 / P-521, DER and IEEE P1363 formats | .NET BCL | FIPS 186-5 |
| ECDSA secp256k1 (SHA-256 prehash, 64-byte compact) | NBitcoin.Secp256k1 | SEC 2 |
| BLS12-381 G1 and G2 variants, with hash-to-curve | Nethermind.Crypto.Bls | RFC 9380 |
| BBS (multi-message, selective disclosure) | zkryptium via Rust FFI | draft-irtf-cfrg-bbs-signatures-10 |

### 2.2 Signatures — new

| Scheme | Driver | Notes |
|---|---|---|
| Recoverable secp256k1 ECDSA (65-byte, recovery id) | `did:ethr`, EVM payments | Signature over a Keccak-256 digest; recovery of the signing public key from signature + digest |

### 2.3 Key agreement and derivation — migrates

- X25519 key agreement (NSec), including the HKDF-SHA256 convenience wrapper.
- Raw ECDH shared-secret derivation ("Z", no KDF) for X25519 and all three NIST P-curves (P-256, P-384, P-521 — confirmed in `DefaultCryptoProvider.DeriveSharedSecret`; P-521 is exercised by didcomm-dotnet).
- Concat KDF (NIST SP 800-56A) and HKDF-SHA256.
- Ed25519 → X25519 birational key derivation (key pair and public-key-only forms).

### 2.4 Hashing — new public surface

| Function | Driver |
|---|---|
| SHA-256 / SHA-384 / SHA-512 helpers | `credentials-dotnet` (SD-JWT disclosure hashing); already used internally |
| Keccak-256 (original Keccak padding — **not** NIST SHA3-256) | `did:ethr` address derivation and transaction digests |

### 2.5 Symmetric encryption and key wrapping — new

All driven by DIDComm v2.1 (`didcomm-dotnet`):

| Primitive | Source | Notes |
|---|---|---|
| AES-256-GCM (A256GCM) | BCL `AesGcm` | DIDComm anoncrypt/authcrypt content encryption |
| AES-256-CBC + HMAC-SHA-512 (A256CBC-HS512) | Composed from BCL | Composite AEAD per RFC 7518 §5.2; non-trivial enough to warrant a tested helper |
| AES Key Wrap (A256KW) | Implement or source (not in BCL) | RFC 3394; required by ECDH-ES+A256KW and ECDH-1PU+A256KW |
| XChaCha20-Poly1305 (XC20P) | **Open** — requires libsodium-backed source | Optional DIDComm suite; see §10 |

### 2.6 Key model, generation, and storage — migrates

- `KeyType` enum (Ed25519, X25519, P-256/384/521, secp256k1, BLS12-381 G1/G2) and the `KeyType ⇄ multicodec` mapping.
- `KeyPair`, `PublicKeyReference`, `StoredKeyInfo`, including `MultibasePublicKey` (multicodec-prefixed, base58btc-multibase public key) via `net-cid`.
- `IKeyGenerator` — random generation, restore-from-private-key, public-only references.
- EC point validation and SEC1 point decompression utilities.
- **Signing abstraction:** `ISigner` with `KeyPairSigner` (in-memory) and `KeyStoreSigner` (HSM/vault-backed via `IKeyStore`; private key never leaves the store). Moves here because every domain library signs.
- **Key storage abstraction:** `IKeyStore`. Concrete stores (file, cloud KMS, enclave) remain out of scope for v1 beyond what migrates.

### 2.7 Key representation — migrates

- `JwkConverter`: JWK (RFC 7517) ⇄ raw key bytes + `KeyType`, both directions, for all supported key types. NetCrypto is the one place that understands every key representation in the stack: raw bytes, multibase, JWK.
- Scope is the JWK *key object* only — no JWS/JWE/JOSE envelope machinery (that is `dataproofs-dotnet` / `didcomm-dotnet` territory).

### 2.8 Dependency-injection integration

A service-collection extension (`AddNetCrypto()`) registering the default providers — `ICryptoProvider`, `IBbsCryptoProvider`, `IKeyGenerator` — via `TryAdd`, so consumer registrations win (the Posture-1 swap seam). **No default `IKeyStore` is registered**: no default store implementation exists; consumers register their own, and signers are obtained from `KeyPair`s (`KeyPairSigner`) or from a store via `IKeyStore.CreateSignerAsync`. Modeled on `net-did`'s DI package.

## 3. Out of scope

| Excluded | Where it lives | Rationale |
|---|---|---|
| CBOR encoding | BCL `System.Formats.Cbor`, used directly by `dataproofs-dotnet` | CBOR is an encoding, not a cryptographic primitive; `net-cid` is the stack's encoding layer |
| Data Integrity proof engine (`eddsa-jcs-2022`) | Stays in `net-did` until `dataproofs-dotnet` exists | Decided 2026-06-09: no temporary double-move |
| JCS canonicalization | `net-cid` (`JcsCanonicalizer`) | Already decided; `net-did`'s private copy retires separately |
| JOSE / COSE / SD-JWT envelope formats | `dataproofs-dotnet` | Token formats, not primitives |
| ECDH-1PU assembly | `didcomm-dotnet` | Composable from `DeriveSharedSecret` + Concat KDF; not a new primitive |
| EVM transaction assembly (RLP, EIP-1559, chain ids) | `net-wallet-sdk` payments layer | NetCrypto stops at "recoverable signature over a Keccak-256 digest" |
| DID / VC / capability semantics | Domain libraries | Foundation layer carries no domain knowledge |
| Concrete HSM / KMS key-store implementations | Future satellite packages or consumers | v1 ships the abstraction plus what migrates |

## 4. Dependencies and boundaries

**Depends on:** `net-cid` — multibase/multicodec encoding for `MultibasePublicKey` and the `KeyType ⇄ multicodec` map — plus external crypto backends: NSec.Cryptography (Ed25519/X25519), NBitcoin.Secp256k1, Nethermind.Crypto.Bls (BLS12-381), the zkryptium Rust FFI (BBS), and the .NET BCL (NIST ECDSA, ECDH, AES, SHA-2, HMAC, HKDF).

> **Reconciliation note.** This supersedes `architectural-path.md` §5.2's "depends on external crypto only." §5.2 and `dependency-stack.svg` (add the `crypto-dotnet → net-cid` arrow) are to be corrected accordingly. Tracked as a separate documentation task — those artifacts live outside the `crypto-dotnet` repository and are therefore not a PRD deliverable.

**Used by:** `net-did` (after refactor), `dataproofs-dotnet`, `credentials-dotnet`, `didcomm-dotnet`, and indirectly everything above them.

**Boundary rules:**

- No type from NSec, NBitcoin, Nethermind, or the FFI appears in any public signature. Public surface speaks in `byte[]`/spans, `KeyType`, and NetCrypto's own types — with two sanctioned exceptions: `NetCid` types (the decided encoding dependency) and `Microsoft.IdentityModel.Tokens.JsonWebKey` in the JWK conversion APIs (retained for v1 parity with `net-did`; a native JWK model is a possible v2 item).
- `System.Text.Json` only, consistent with the stack-wide standard (relevant to `JwkConverter`).
- Target framework: .NET 10. `AllowUnsafeBlocks` retained only as required by the FFI layer.

## 5. Architecture posture

**Single provider, swappable via DI (Posture 1).** One `DefaultCryptoProvider` implements `ICryptoProvider` for all key types; consumers with special requirements replace the DI registration. Two commitments follow:

1. The per-algorithm decomposition inside `DefaultCryptoProvider` (Ed25519, NIST ECDSA, secp256k1, BLS groups) stays cleanly separated, as it largely is today.
2. The designated evolution path, should a validated-crypto (FIPS 140-3) requirement materialize, is a per-`KeyType` provider registry behind the *unchanged* `ICryptoProvider` facade — an internal, non-breaking restructuring plus an additive registration API. No registry is built in v1.

**BBS ciphersuite parameterization.** `IBbsCryptoProvider` operations take a `BbsCiphersuite` parameter (or provider-level setting), defaulting to `Bls12381Sha256` — the only implemented value in v1 (it is what zkryptium wires and what W3C `bbs-2023` mandates). `Bls12381Shake256` and future suites become additive, non-breaking extensions. Terminology standardizes on **"BBS"** (the CFRG name) throughout code and docs, with a note that this is the scheme historically called BBS+.

## 6. Native component: distribution and optionality

BBS is the only non-managed primitive: zkryptium (Rust) compiled per platform, consumed over P/Invoke (`[LibraryImport]`, six C-ABI functions).

**Distribution (decided):** the repository stays source-only — no compiled binaries in git. At release, CI cross-compiles the FFI crate for all five supported RIDs (`osx-arm64`, `osx-x64`, `linux-x64`, `linux-arm64`, `win-x64`) and packs them into the single `NetCrypto` NuGet package under `runtimes/{rid}/native/`. Every shipped binary is traceable to a CI run from tagged source. This corrects `net-did`'s current state, where only the `osx-arm64` binary is committed and BBS fails on every other platform.

**Optionality (decided — supported mode):** all managed primitives function with no native library present. BBS operations throw a documented, specific exception when the native library is unavailable, and a capability check (e.g. `IsBbsAvailable`) lets consumers probe before use. This is a supported, documented, tested configuration — for unlisted platforms (e.g. Alpine/musl) and environments that prohibit loading native code. The existing lazy-probe behavior in `DefaultBbsCryptoProvider` is the basis.

## 7. Downstream adoption (separately tracked — not part of the NetCrypto PRD)

`net-did` and `didcomm-dotnet` will depend on NetCrypto. Their adoption refactors are executed in *their* repositories as individually tracked work items, sequenced **after** NetCrypto v1 ships; the NetCrypto PRD's scope ends at the published, fully verified package (decision 11). This section describes the net-did adoption item so its shape is on record.

A relocation refactor, behavior-preserving:

- `Crypto/` (except `DataIntegrity/` and `Jcs/`), `Jwk/`, the four interfaces, `IKeyStore`, and `native/zkryptium-ffi/` move to `crypto-dotnet`; `net-did` adds a `NetCrypto` package reference and re-points namespaces.
- `NetDid.Core` drops its direct references to NSec, NBitcoin.Secp256k1, and Nethermind.Crypto.Bls, and its `runtimes/` payload.
- The Data Integrity engine and the private JCS canonicalizer stay in `net-did` for now (their migrations are deferred to the `dataproofs-dotnet` and `net-cid` adoption work respectively).
- Existing `net-did` crypto tests migrate with the code and must pass unchanged — they are the behavior-parity oracle.

A second adoption item follows for `didcomm-dotnet`: deleting its internal A256GCM / A256CBC-HS512 / A256KW / XC20P implementations and re-pointing its Concat-KDF imports to NetCrypto. Planned after the net-did adoption.

## 8. Success criteria

**Package-level (v1 — verified inside `crypto-dotnet` by the PRD):**

1. All migrated tests (copied in from `net-did`) pass relocated, unmodified in assertion content; golden parity values (e.g. multibase outputs) match those captured from `net-did` before migration.
2. The packed `NetCrypto` NuGet contains working native BBS payloads for all five RIDs; BBS is smoke-executed in CI on every RID with an available hosted runner (at minimum linux-x64, osx-arm64, win-x64), with the remaining RIDs verified by packaged-binary presence and checksums.
3. The no-native-library mode is exercised in CI: managed primitives pass, BBS throws the documented exception, the capability check reports correctly.
4. New primitives (Keccak-256, recoverable secp256k1, AEADs incl. XC20P, AES-KW, hashing helpers) are covered by test vectors from their governing specifications.
5. No public API exposes a backend library type (per the §4 boundary rules and their sanctioned exceptions); enforced by a public-API analyzer.
6. The public surface is complete for downstream needs: every primitive that `net-did`, `dataproofs-dotnet`, `credentials-dotnet`, and `didcomm-dotnet` require (per §2's per-consumer drivers) exists in `NetCrypto`, so each can declare its crypto needs against `NetCrypto` alone.

**Program-level (proven by the separately tracked adoption items of §7, not gating the v1 package):**

7. `net-did` compiles and passes its full test suite against `NetCrypto`, with its own crypto sources deleted.
8. `didcomm-dotnet` builds against `NetCrypto` with its internal AEAD/key-wrap copies deleted, with no `net-did` dependency for crypto.

## 9. Decision record

| # | Decision | Outcome | Date |
|---|---|---|---|
| 1 | Encoding boundary | NetCrypto depends on `net-cid`; key model keeps `MultibasePublicKey` | 2026-06-09 |
| 2 | v1 primitive scope | Comprehensive: everything existing + did:ethr, credentials, and DIDComm needs; CBOR excluded | 2026-06-09 |
| 3 | Signing / key storage abstractions | `ISigner`, `KeyPairSigner`, `KeyStoreSigner`, `IKeyStore` move to NetCrypto | 2026-06-09 |
| 4 | Data Integrity engine | Stays in `net-did` until `dataproofs-dotnet` is built | 2026-06-09 |
| 5 | JWK conversion | `JwkConverter` moves to NetCrypto | 2026-06-09 |
| 6 | BBS naming + ciphersuite | Standardize on "BBS"; parameterize ciphersuite, default `Bls12381Sha256` | 2026-06-09 |
| 7 | Native distribution | Source-only repo; CI cross-compiles 5 RIDs into one `.nupkg` | 2026-06-09 |
| 8 | BBS optionality | "No native library" is a supported, documented mode with capability check | 2026-06-09 |
| 9 | Package / namespace | `NetCrypto`, single package for v1; repo remains `crypto-dotnet` | 2026-06-09 |
| 10 | Crypto agility | Posture 1: single provider swappable via DI; per-`KeyType` registry is the documented, non-breaking evolution path | 2026-06-09 |
| 11 | Downstream adoption scope | `net-did` and `didcomm-dotnet` adoption of NetCrypto are separately tracked work items executed in their own repositories after v1 ships; the NetCrypto PRD ends at the published package | 2026-06-10 |

## 10. Open questions and risks

**Open questions (to resolve during PRD):**

1. **XChaCha20-Poly1305 (XC20P)** — include in v1 (requires a libsodium-backed dependency; NSec exposes ChaCha20-Poly1305 but the *X* variant needs checking) or defer until `didcomm-dotnet` confirms it will support the XC20P suite at all? **→ Resolved (PRD, 2026-06-09): in scope for v1.** Inspection of `didcomm-dotnet` showed NSec exposes `AeadAlgorithm.XChaCha20Poly1305` directly (its `XChaCha20Poly1305Aead` is a thin pass-through), so no new dependency is needed and the suite is already in use downstream.
2. **Recoverable secp256k1 source** — NBitcoin.Secp256k1's recoverable-signature support is the expected path; confirm coverage of recovery-id conventions used by EVM (v ∈ {27, 28} / EIP-155 adjusted) or whether that adjustment belongs in the wallet layer.
3. **Keccak-256 source** — Nethermind ecosystem implementation vs. a minimal vendored implementation; decide on dependency-weight grounds.
4. **CI cross-compilation details** — runner matrix (macOS runners for the two Apple RIDs), Rust toolchain pinning, and whether release artifacts get checksummed/signed.

**Risks:**

| Risk | Severity | Mitigation |
|---|---|---|
| BBS is an IETF Internet-Draft (draft-10), not a final RFC; wire format may change between drafts | Medium | Conformance pinned to draft-10 via zkryptium 0.6; ciphersuite parameter and FFI isolation contain the churn; track CFRG progress |
| No backend (NSec, NBitcoin, Nethermind, zkryptium) is independently audited or FIPS-validated | Medium | Documented openly; Posture 1 evolution path (§5) is the FIPS answer; plan an audit before any high-assurance claim |
| Composite AEAD (A256CBC-HS512) and AES-KW are easy to implement subtly wrong | Medium | Implement strictly against RFC 7518 §5.2 / RFC 3394 test vectors; no shortcuts |
| Multi-platform native CI is new infrastructure | Low–Medium | One-time setup; per-RID smoke tests in CI (success criterion 3) |
| Keccak-256 confusion with NIST SHA3-256 | Low | Naming and docs make the distinction explicit; test vectors from Ethereum |

## Appendix A — Glossary

- **AEAD** — Authenticated Encryption with Associated Data: encryption that also guarantees integrity of the ciphertext and of attached cleartext metadata.
- **BBS** — the CFRG multi-message signature scheme enabling selective disclosure via zero-knowledge proofs; historically called BBS+.
- **Ciphersuite** — a fixed bundle of parameter choices (hash, domain-separation tags) that both parties to a scheme must share exactly.
- **FFI** — Foreign Function Interface; here, C# calling a Rust-built native library via P/Invoke.
- **FIPS 140-3** — the U.S. standard for *validated* cryptographic modules; concerns whose implementation runs, not which algorithm.
- **JWK** — JSON Web Key (RFC 7517), the JSON representation of a cryptographic key used throughout JOSE.
- **Keccak-256** — the hash Ethereum uses; the original Keccak submission, with padding different from NIST's finalized SHA3-256.
- **Multibase / multicodec** — self-describing encodings from the multiformats suite (implemented in `net-cid`); `MultibasePublicKey` is a multicodec-prefixed, base58btc-encoded public key.
- **RID** — .NET Runtime Identifier (e.g. `linux-x64`), naming an OS+CPU target for native assets.
- **Recoverable ECDSA** — an ECDSA variant whose signature carries a recovery id allowing derivation of the signer's public key from signature + digest; how Ethereum identifies transaction senders.
