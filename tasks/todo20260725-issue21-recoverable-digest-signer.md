# Issue #21 — IRecoverableDigestSigner abstraction → release 1.4.0

Deploy issue #21 as NetCrypto 1.4.0: expose a recoverable digest-signer
abstraction so HSM/key-store-held secp256k1 keys can produce EVM signatures
(raw recid only — FR-12 boundary preserved verbatim, no keccak, no v-encoding).

## Plan

- [ ] `RecoverableSignature` readonly record struct (Signature64, RecoveryId) with FR-12 boundary XML docs
- [ ] `IRecoverableDigestSigner` interface (KeyType, PublicKey, SignDigestAsync)
- [ ] `KeyPairSigner : IRecoverableDigestSigner` — borrow pattern via `WithPrivateKey`, secp256k1-only (NotSupportedException otherwise), disposed → ObjectDisposedException, digest32 length-validated first
- [ ] `IKeyStore.SignDigestAsync` — DIM default throwing NotSupportedException (external stores keep compiling, opt in explicitly)
- [ ] `InMemoryKeyStore.SignDigestAsync` — alias validation (KeyNotFoundException), secp256k1-only, borrow + `Secp256k1Recoverable.Sign`
- [ ] `KeyStoreSigner : IRecoverableDigestSigner` — validates digest locally, delegates to the store
- [ ] `PublicAPI.Unshipped.txt` entries for everything new (analyzer-verified)
- [ ] Tests: round-trip vs `Secp256k1Recoverable.RecoverPublicKey` oracle, low-S, RFC 6979 determinism, EIP-155 external vector, full negative matrix (31/33/0-byte digest, wrong key types, disposed, DIM default, unknown alias, null/empty alias)
- [ ] EvmSigning sample: new IRecoverableDigestSigner section (satisfies FR-17 ApiCoverageCheck for the new names)
- [ ] CHANGELOG `[1.4.0]`; PRD FR-12b + traceability/FR-17 table rows; Directory.Build.props → 1.4.0
- [ ] Full solution build `-warnaserror` + all tests + samples + ApiCoverageCheck green locally
- [ ] Adversarial exploitation pass (L4/L6 — mandatory, even for "thin delegation")
- [ ] Branch `feat/recoverable-digest-signer-issue-21` → PR (Closes #21) → build CI green → merge
- [ ] Annotated tag `v1.4.0` on the merge commit → push → release CI (pack, smoke, GitHub release, NuGet publish) verified

## Review

**Delivered (all local gates green):**
- `RecoverableSignature` record struct + `IRecoverableDigestSigner` interface, both with FR-12
  boundary XML docs (raw recid only; no keccak; no v-encoding).
- `KeyPairSigner` and `KeyStoreSigner` implement the interface; `InMemoryKeyStore` and the
  `IKeyStore` DIM default (throwing `NotSupportedException`) implement/expose `SignDigestAsync`.
  Signing goes through the `KeyPair.WithPrivateKey` borrow (no private-key heap copy, per #17).
- Input contract: digest length ≠ 32 → parameter-named `ArgumentException` before any crypto op
  at every entry point; non-secp256k1 → `NotSupportedException` naming the type; unknown alias →
  `KeyNotFoundException`; disposed → `ObjectDisposedException`.
- Tests: 23 new cases (round-trip vs `RecoverPublicKey` oracle on all three paths, low-S, RFC 6979
  determinism, EIP-155 external vector through both KeyPair and key-store paths, full negative
  matrix, DIM source-compat proof, all-zero-digest opacity). Full suite 936 passed.
- Sample: `EvmSigning` extended with an `IRecoverableDigestSigner` section (also satisfies the
  FR-17 ApiCoverageCheck for the new names). All 10 samples exit 0; coverage check green.
- Docs/version: CHANGELOG `[1.4.0]`, PRD FR-12b + traceability/FR-17 rows, version → 1.4.0.

**Verification:** `dotnet build NetCrypto.sln -warnaserror` (0 warnings), `dotnet test` (936/936),
all samples exit 0, ApiCoverageCheck OK.

**Adversarial pass (L4/L6):** independent agent ran 57 write-and-run exploit tests — byte-parity
with `Secp256k1Recoverable.Sign` (no hidden hashing/v-encoding), every malformed-input path maps
to the correct contract exception (zero leaked IOOR/NRE/backend exceptions), disposed-mid-flight
borrow → `ObjectDisposedException` not a half-wiped signature, race-free under real parallelism.
**Zero findings.**

**Lesson captured:** L7 — an energetic "Go" authorizes the goal, not skipping the plan-approval
check-in; present the plan before the first edit, especially for release tasks.

**Release:** paused before merge per user's choice; PR opened, awaiting CI + user review before
merge → tag `v1.4.0` → release CI (NuGet publish).

## Review round 2 (PR #22 feedback — two review sets)

Two reviews landed: an LGTM comment (minor notes) and a formal COMMENTED review ("would not merge
as written") with three reproduced failures. I reproduced all three against the committed code,
confirmed valid, and fixed:

1. **Alias rebinding silently changed signer identity** (delete + recreate alias → old signer
   emits a signature that recovers to the NEW key while advertising the OLD one). VALID.
2. **Malformed store output passed through** `KeyStoreSigner` unchanged (`RecoverableSignature([0x01], 27)`
   accepted). VALID.
3. **DIM default violated the "every entry point" contract** — 31-byte digest → `NotSupportedException`
   instead of parameter-named `ArgumentException("digest32")`. VALID.

**Fixes:**
- `KeyStoreSigner.SignDigestAsync` now verifies the store's output at the boundary: structural
  check (64-byte `R‖S`, recid 0–3) + recover-and-compare against the advertised `PublicKey` →
  `CryptographicException` on mismatch. Closes (1) and (2) together.
- `IKeyStore.SignDigestAsync` DIM default validates digest length before throwing `NotSupported`.
  Closes (3).
- `RecoverableSignature` reference-equality documented (LGTM note 1a); CHANGELOG date → 2026-07-26
  (note 1c). Note 1b (KeyStoreSigner defers secp256k1 check to store) — reviewer said correct as
  written; no change.

**Regression tests (+7, suite now 943):** alias-rebind → `CryptographicException`; advertised-key
mismatch → `CryptographicException`; malformed store output → `CryptographicException`; valid
store output still round-trips; DIM default wrong-length (0/31/33) → `ArgumentException("digest32")`.

**Public API unchanged** (behavioral fix only — private helper + DIM body). Full solution build
`-warnaserror` clean, 943 tests, all samples, ApiCoverageCheck green.

**Lesson L8:** adversarial coverage for a delegation/boundary type must probe state-mutation-under-
a-live-handle and full backend-output passthrough, not just input guards — the first pass's "zero
findings" certified input handling, not boundary integrity.
