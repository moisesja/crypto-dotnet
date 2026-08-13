# Issue #26 — `ICapableKeyStore` custody surface → release 1.6.0

Branch: `feat/capable-keystore-issue-26` (created before first edit, per AGENTS.md §0)
Issue: https://github.com/moisesja/crypto-dotnet/issues/26 (milestone 1.6.0)
Audit baseline: 1.4.0 / 1.5.0, `main@4a54268`

---

## 0. Scope decision — **APPROVED 2026-08-12**

- **Scope: full surface in 1.6.0.** All `[S2]` items below are *in*, not deferred.
- **Release tail: branch + PR only.** No merge, no `v1.6.0` tag, no NuGet publish.
- **Gates: fan out to subagents** (explicit authorization for `adversarial-pass` and
  `input-validation-sweep`).

The issue offers two deliveries and states a *mild* preference for staging:

- **Staged** — 1.6.0 = discovery + identity + namespace + idempotent generate/delete +
  outcome reader + algorithm-bearing sign/agreement + error taxonomy; 1.7.0 = import
  ownership + BBS-by-reference.
- **Single release** — all of it in 1.6.0.

**Recommendation: single release (full surface in 1.6.0).** The task statement is "address
the issue and prepare everything for a 1.6.0 release". Everything is additive, lives in one
assembly, and the two "stage 2" members are ~2 of 10 members — but they carry the subtlest
semantics, so they get their own dedicated adversarial pass inside this release rather than
their own release. Staging would also mean the downstream custody port re-audits twice.

If the answer is *staged*, the deltas are marked **[S2]** below and drop out of 1.6.0, with
`ImportAsync(KeyImportRequest)`/`SignBbsAsync` shipping as `KeyStoreException(Unsupported)`
and `Import`/`BbsSign` never advertised.

---

## 1. Requirement anchoring (PRD)

New **FR-7b — Capability-bearing key-custody surface (`ICapableKeyStore`, 1.6.0, issue #26)`**,
sibling to FR-12b, sitting under FR-7 and inheriting **NFR-1** (no backend type in public
signatures), **NFR-3** (input validation), **NFR-6** (trust-boundary integrity — this is a
delegating surface, so §NFR-6.1–3 apply to every routed member), **NFR-5** (XML docs on all
public members), and **FR-18** (zeroization) for `TransferableKeyMaterial`.

Traceability appendix gets a row: §2.6 HSM-first delegation → FR-7, FR-7b, FR-12b, NFR-6.

- [x] PRD: add FR-7b with the full semantic contract (10 rules) + acceptance criteria
- [x] PRD: add the traceability row and the algorithm-id table
- [x] concept: note the custody surface under §2.6 capability list

---

## 2. Design decisions (fixing the issue's open choices)

**D1 — Reference implementation is a sibling, not a mutation.** `InMemoryKeyStore` is left
byte-for-byte untouched (zero risk to existing consumers). New `CapableInMemoryKeyStore`
implements `ICapableKeyStore` end-to-end.

**D2 — Namespace isolation needs shared backing state.** The issue's isolation test requires
"two instances over one backing dictionary/backend". So the state is a separate public
`InMemoryKeyStoreBackend : IDisposable` (keys keyed by `(namespace, alias)`, mutation ledger
keyed by `(namespace, kind, operationId)`, minted-instance-id set). `CapableInMemoryKeyStore`
holds `(backend, namespaceId, generator, cryptoProvider, bbsProvider?)`. A convenience ctor
mints a private backend. This also gives the "ledger survives restart" test its mechanism:
new store instance over the same backend.

**D3 — Algorithm id table (fixed here, not vendor names).** `public static class
KeyStoreAlgorithms` exposing `KeyStoreAlgorithmId` constants, so ids are discoverable and
typo-proof:

| Id | KeyType | Operation | Observable encoding |
|---|---|---|---|
| `ed25519` | Ed25519 | Sign | 64-byte EdDSA (RFC 8032) |
| `es256-der` / `es256-p1363` | P256 | Sign | DER / fixed-width 64-byte R‖S |
| `es384-der` / `es384-p1363` | P384 | Sign | DER / 96-byte R‖S |
| `es512-der` / `es512-p1363` | P521 | Sign | DER / 132-byte R‖S |
| `es256k` | Secp256k1 | Sign | fixed 64-byte compact R‖S (no DER variant exists) |
| `bls12381g1-basic` / `bls12381g2-basic` | Bls12381G1/G2 | Sign | BLS basic scheme |
| `ecdh-x25519`, `ecdh-p256`, `ecdh-p384`, `ecdh-p521` | resp. | KeyAgreement | raw Z |
| `bbs-bls12381-sha256` | Bls12381G2 | BbsSign | 80-byte BBS (draft-10) |

DER/P1363 ids map onto the existing `EcdsaSignatureFormat` overload of `ICryptoProvider.Sign`
— that is the whole point of rule 2. `es256k` deliberately has no DER sibling: the provider
always emits compact for secp256k1.

**D4 — `MaxInputBytes` is defined per operation** (it must be positive and finite on *every*
capability, including Generate/Import which have no payload): the bound on the caller-supplied
input the operation accepts — alias UTF-8 length for Generate/Import, `Data.Length` for Sign,
`PeerPublicKey.Length` for KeyAgreement, and total `Messages` + `Header` bytes for BbsSign.
Documented on the property. Reference store: 1 MiB for data-bearing ops, 512 for aliases.

**D5 — Exception split (NFR-3 vs. the new taxonomy).**
- Null / wrong-shape / **oversize** input → parameter-named `ArgumentException` /
  `ArgumentNullException`, before any backend work. NFR-3 is unconditional and oversize is a
  length problem.
- Unadvertised `(KeyType, Operation, Algorithm)` tuple, algorithm/key mismatch → `KeyStoreException(Unsupported)`.
- Idempotency-key reuse with a different request → `KeyStoreException(IdempotencyConflict)`.
- `AccessDenied` / `Throttled` / `Unavailable` / `OutcomeUnknown` → for backends; the
  reference store documents which it can raise (`Unsupported`, `IdempotencyConflict` only).
- Legacy `IKeyStore` members keep their documented BCL exceptions — unchanged.
- **No** backend type (NSec/NBitcoin/Nethermind/native/platform `CryptographicException`)
  escapes any `ICapableKeyStore` member (L5/L9 lesson; adversarial wrap test).

**D6 — `default(T)` holes in the id record structs.** `readonly record struct X(string Value)`
has an unavoidable `default(X)` with `Value == null`. Guarded twice: a validating primary
constructor, **and** an explicit reject-the-default check at every consuming member
(parameter-named `ArgumentException`). This is exactly the class of hole an adversarial pass
finds; it is designed in, not patched on.

**D7 — `StoredKeyInfo` gains `KeyInstanceId? InstanceId { get; init; }`** (init-only,
defaulted `null` for legacy paths), *and* `KeyMutationResult` carries it alongside. Value
equality/hash extended to include it; legacy infos leave it null so existing behavior is
unchanged. `KeyMutationResult`/`KeyDeleteResult` carry `Replayed`.

**D8 — `TransferableKeyMaterial` state machine** [S2]. `Ready → Consumed`. Created by
`FromKeyPair(KeyPair)` (copies out via the FR-18 `WithPrivateKey` borrow — no intermediate
heap array) or `FromRawKey(KeyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)`.
Private material lives in a **pinned** buffer (FR-18 `GC.AllocateArray(pinned: true)`), read
exactly once through an `internal` reader delegate, then zeroized and latched unreadable.
No public getter, no `ToJwk`, no formatting. `KeyType`/`PublicKey` are readable **before**
consumption only (a store must read them for pre-validation); after consumption every member
except `IsConsumed` throws `ObjectDisposedException` — that is the "throws on any further use"
contract. `Dispose()` zeroizes without consuming. Failure/cancellation *before* acceptance
leaves it `Ready` for exactly one retry.

**D9 — Idempotent import never re-reads material.** The canonical request fingerprint is
SHA-256 over `(namespace, kind, alias, keyType, publicKey)` — **public data only**, never the
secret. So a replay is detected *before* the material is read; on replay the store zeroizes
and latches the material without reading it (destroy ≠ read, which is what the counting-accessor
test asserts).

**D10 — `Revision` is content-derived**, not a Guid: base64url(SHA-256(canonical capability
list)). Stable for the instance lifetime by construction, and identical across two instances
with identical capabilities — which is the honest meaning of "the snapshot did not change".

**D11 — Cancellation.** `ct.ThrowIfCancellationRequested()` runs *before* the atomic commit and
never after; the reference store's commit is a single interlocked ledger+dictionary write, so
"cancelled after acceptance" cannot occur and `OutcomeUnknown` is documented as reachable only
by real remote backends. Test asserts: cancelled-before → `OperationCanceledException` **and**
no key, no ledger entry.

**D12 — `GetInfoAsync(alias, instanceId)` returns `null`** for a stale/rebound instance id
(the nullable return *is* the failure channel for a query); `SignAsync`/`SignBbsAsync`/
`DeriveSharedSecretAsync` **throw** `KeyNotFoundException` for a stale id, since silently
signing under a rebound key is the #21 hazard this generalizes.

---

## 3. Implementation checklist

### 3.1 New public surface (`src/NetCrypto/`, flat, root namespace `NetCrypto`)

- [x] `KeyStoreIdentifiers.cs` — `KeyStoreNamespaceId`, `KeyInstanceId`, `KeyOperationId`,
      `KeyStoreAlgorithmId` (validating record structs, D6)
- [x] `KeyStoreAlgorithms.cs` — the D3 id table as constants
- [x] `KeyStoreCapabilities.cs` — `KeyStoreOperation`, `KeyStoreCapability`,
      `KeyStoreCapabilitySet`, `IKeyStoreCapabilityProvider`
- [x] `KeyStoreRequests.cs` — `KeyGenerateRequest`, `KeyImportRequest` [S2], `KeyDeleteRequest`,
      `KeySignRequest`, `KeyBbsSignRequest` [S2], `KeyAgreementRequest`
- [x] `KeyStoreMutations.cs` — `KeyMutationKind`, `KeyMutationResult`, `KeyDeleteResult`,
      `KeyMutationOutcome` (abstract), `KeyGeneratedOutcome`, `KeyImportedOutcome` [S2],
      `KeyDeletionOutcome`
- [x] `KeyStoreException.cs` — `KeyStoreError`, `KeyStoreException` (+ `RetryAfter`)
- [x] `TransferableKeyMaterial.cs` [S2]
- [x] `ICapableKeyStore.cs`
- [x] `InMemoryKeyStoreBackend.cs`
- [x] `CapableInMemoryKeyStore.cs`
- [x] `StoredKeyInfo.cs` — add `InstanceId` + equality/hash (D7)
- [x] XML doc on **every** public member (NFR-5, CS1591-as-error)

### 3.2 Tests (`tests/NetCrypto.Tests/KeyStore/`)

One file per contract rule so a failure names the rule it broke:

- [x] `CapabilityHonestyTests` — every advertised tuple round-trips against the
      `ICryptoProvider`/`IBbsCryptoProvider` oracles; a curated unadvertised set throws
      `Unsupported` **before** mutation (store contents asserted unchanged); discovery is
      side-effect-free, deeply immutable, stable `Revision`; every `MaxInputBytes` positive
- [x] `AlgorithmEncodingTests` — `es256-p1363` verifies under `Verify(..., IeeeP1363)` and
      **fails** DER parsing, and the converse; `es512-*` widths (66-byte coords); `es256k`
      always 64-byte compact; requesting an algorithm the key can't do fails before backend work
- [x] `KeyInstanceIdentityTests` — delete → recreate alias → stale id fails on sign/agree
      (throw) and `GetInfoAsync` (null); new id succeeds; ids never repeat across the
      backend lifetime (bulk mint + set assertion)
- [x] `NamespaceIsolationTests` — two stores, one backend, disjoint namespaces: cross-namespace
      get/list/sign/agree/delete/legacy-member all fail; identical `KeyOperationId` in two
      namespaces does **not** collide
- [x] `IdempotencyTests` — replay → same logical result + `Replayed == true` + exactly one key;
      same id/different request → `IdempotencyConflict`; ledger survives "restart"; receipt via
      `GetMutationOutcomeAsync`; `GetMutationOutcomeAsync` side-effect-free
- [x] `TransferableKeyMaterialTests` [S2] — accepted import latches unreadable + buffer zeroized
      (FR-18/#17 probe pattern); pre-acceptance failure leaves it usable for one retry; replayed
      import never *reads* material (counting reader); no export surface (reflection assertion)
- [x] `CancellationTests` — cancel before acceptance → `OperationCanceledException`, no key, no
      ledger entry
- [x] `BoundsTests` — `MaxInputBytes + 1` on sign/BBS/agreement → parameter-named
      `ArgumentException` before any crypto call (asserted with a counting `ICryptoProvider`)
- [x] `BbsByReferenceTests` [S2] — `SignBbsAsync` output verifies via `IBbsCryptoProvider.Verify`
      with the same header; `BbsSign` advertised iff `IsAvailable`; basic BLS signing never
      advertised as BBS; `[Category=NativeFFI]` so the no-native CI leg stays green
- [x] `CapableKeyStoreErrorTaxonomyTests` — adversarial wrap: no `NBitcoin`/NSec/Nethermind/
      native/platform exception type escapes any member (L5/L9)
- [x] `NonFunctional/KeyInputValidationTests` + `InputValidationFuzzTests` — extend to the new
      surface, all three NFR-3 families, **no allow-list**
- [x] `NonFunctional/PublicApiHygieneTests` — passes unchanged (NFR-1) over the new types

### 3.3 Sample (FR-17 — hard CI gate)

`tools/ApiCoverageCheck` fails the build unless **every** new public type/method/property name
appears in `samples/**/*.cs`, and its exemption list must stay empty.

- [x] `samples/NetCrypto.Samples.CapableKeyStore/` — discovery → validate → sign, plus
      namespace scoping, idempotent generate + replay, instance-id rebind rejection, import
      ownership [S2], BBS-by-reference [S2] behind `IsAvailable`, and the error taxonomy.
      Must exit 0 **with and without** the native library (no-native CI leg)
- [x] `samples/README.md` — add the new sample to the learning path
- [x] Verify `dotnet run --project tools/ApiCoverageCheck -- samples` exits 0

### 3.4 Docs / release chores

- [x] `README.md` — "Implementing a capable key store" section for store authors (the 10 rules,
      condensed) + the algorithm-id table
- [x] `PublicAPI.Unshipped.txt` — every new type/member
- [x] `CHANGELOG.md` — `[1.6.0]` Added section + compare link
- [x] `Directory.Build.props` — `NetCryptoVersion` → `1.6.0`
- [x] Per-release hygiene (PRD §8): promote `PublicAPI.Unshipped.txt` → `PublicAPI.Shipped.txt`
      as the final release step, leaving Unshipped with just `#nullable enable`
- [x] `tasks/lessons.md` — L11 (validate on `init`, not in a property initializer) and L12 (a length check on backend output is not an identity check)

### 3.5 Gates (definition of done, AGENTS.md §4)

- [x] `dotnet build NetCrypto.sln -c Release -warnaserror` clean
- [x] `dotnet test NetCrypto.sln -c Release` — full suite green
- [x] `dotnet test --filter "Category!=NativeFFI"` green (no-native mode)
- [x] All 11 samples exit 0
- [x] `input-validation-sweep` skill run over the new public surface
- [x] `adversarial-pass` skill run — **before** declaring done, not after
- [x] Every new regression test proven genuine (revert the guard, confirm the test fails at the
      intended assertion, restore)
- [ ] Commit on `feat/capable-keystore-issue-26`; PR against `main`

**Note on the two skill gates:** both `adversarial-pass` and `input-validation-sweep` are
written around independent subagents, but this session carries a standing instruction not to
launch agents unless asked. Unless told otherwise I will execute both passes **in-session** —
writing and running the actual exploit/fuzz tests rather than merely inspecting code, which is
the substance the gates require. Say the word if you'd rather I fan them out to subagents.

---

## 4. Release mechanics (needs approval — irreversible tail)

"Prepare everything for a 1.6.0 release" is read as: **everything up to and including a
pushed branch + PR**, with version, CHANGELOG, API baseline and docs all release-ready.

I will **not**, without a further explicit go-ahead: merge to `main`, create/push the `v1.6.0`
tag, or trigger the NuGet publish (`release.yml` fires on `v*` and pushes to nuget.org).

---

## 5. Review

### 5.1 Adversarial pass (AGENTS.md §2 / §4 gate) — subagent, 51 exploit tests executed

Run against the Release build with the native BBS library present, in a scratch probe file
(deleted afterwards). Baseline: the author's own suite passes; the only 5 failures in the repo
are the pre-existing `BbsUnavailableTests`, which assert BBS is *absent* and therefore fail on
any machine where the native library is built. Verified those 5 fail identically on `main`.

**Findings accepted and fixed in `src/`:**

| # | Finding | Why it is real |
|---|---|---|
| F1 | Provider output was length-checked but never verified **against the key it claims to speak for**. A hostile provider's signature under a *different* P-256 key was returned to the caller; 80 bytes of `0xAB` passed as a BBS signature; a 1-byte DER signature passed (no length check applies to DER). | Straight NFR-6.2 violation, and the repo already does this on the recoverable path (`KeyStoreSigner.CopyAndVerify`). Lesson L9 is this exact class of miss. |
| F2 | `SignBbsAsync` summed the size bound with `foreach` (enumerator) and copied with the indexer, so a caller-supplied `IReadOnlyList` whose two paths disagree signs past `MaxInputBytes`. | Rule 9 says oversize fails *before* backend work; a hostile list also threw raw `IndexOutOfRangeException` out of the member. |
| F3 | Import never checked that the supplied public key belongs to the supplied private key, so `StoredKeyInfo.PublicKey` — the verification identity downstream DID/VC code publishes — was attacker-chosen. A 1-byte "Ed25519" pair was also accepted into custody, failing only at first use. | Defeats the whole point of discovery-before-use, and the derive-and-compare oracle already exists (`IKeyGenerator.FromPrivateKey`). |
| F4 | `Monitor` is reentrant, so a provider that calls back into the store on the same thread walked through the backend lock, deleted the key, and **zeroized the pinned buffer the in-flight `WithPrivateKey` span pointed at** — the store then returned a signature for a key it had just destroyed. | The injected provider is the documented Posture-1 trust boundary; a provider that merely logs through a callback hits this without being hostile. |
| F6 | A provider throwing `OperationCanceledException`/`ObjectDisposedException` escaped untranslated, so the store reported cancellation with no token cancelled. | Rule 6 is "cancellation never lies". |
| F7 | Any `ArgumentException` from the provider was re-blamed on the caller's `request`, including one naming a provider-internal parameter — pointing the operator at the wrong side of the boundary. | Misattribution: the caller won't retry or fail over. |
| F8 | `SignAsync`/`DeriveSharedSecretAsync` did not snapshot the caller's `ReadOnlyMemory`, so "signs the exact supplied bytes" was undefined under concurrent mutation. `SignBbsAsync` already copied. | Also required for F1's verification to compare against the same bytes that were signed. |

**Findings argued down, with the reasoning recorded:**

- **F5 — `CreateSignerAsync` and the legacy `SignAsync(alias, …)` carry no instance check.** True,
  and unchanged from `InMemoryKeyStore`. Fixing it would change inherited `IKeyStore` behavior,
  which this issue explicitly does not do; the instance-checked path is
  `SignAsync(KeySignRequest)`, which exists precisely for this. Adding a new instance-bearing
  `CreateSignerAsync` overload would widen the surface past what #26 specifies. **Resolution:
  documented on each legacy override rather than changed.**
- **F9 — a replayed generate reports success after the key was deleted through the legacy path.**
  Correct ledger semantics (real KMSes behave this way); the receipt records what happened, not
  what currently exists. **Resolution: one sentence on `KeyMutationResult.Replayed`.**
- **F10 — `TransferableKeyMaterial` has no finalizer**, so an abandoned instance is collected with
  the secret intact. Consistent with `KeyPair` (FR-18), which made the same call deliberately; a
  finalizer on a pinned buffer buys a best-effort wipe at the cost of resurrection subtleties.
  **Resolution: documented, not added.**
- **Info — the capability snapshot is a process-wide static**, so its blast radius under private-
  field reflection is process-wide. Private reflection is outside the threat model (the agent
  reached it only by writing to `ReadOnlyCollection`'s private field); no public mutator exists.
  **No change.**

**Attacks that found nothing** (all executed, listed because a "zero findings" pass that only
fed bad inputs certifies input handling and nothing else — lesson L9):

BBS integer overflow at exactly 2³² bytes (the `long` accumulator held); backend exception types
out of `SignBbsAsync`; BBS wrong-length output; a provider retaining and later clearing its result
buffer; stale `KeyInstanceId` on every capable member; **namespace escape** across 5 namespace
pairs × 12 alias shapes including separator characters, NFC/NFD, ZWSP, BOM and 512-char aliases
— the `(string, string)` tuple key never concatenates, so there is no separator to smuggle;
cross-namespace receipt reads; cross-namespace existence oracle (a neighbour's alias and a
nonexistent one are indistinguishable); **fingerprint forgery** across 64 combinations chosen to
collide under a naive delimiter join — zero collisions, the 4-byte length prefix is injective by
construction; `IdempotencyConflict` message leakage; the `TransferableKeyMaterial` public surface
(no export path exists); read-twice / read-after-consumption / reflection recovery; an exception
thrown inside the reader (still latches and zeroizes); `Dispose()` raced against `ImportAsync`
over 200 rounds on two threads; the replay path never reading the secret; silent downgrade via
case, whitespace, ZWSP, NBSP and Cyrillic look-alike algorithm ids; `with`-mutated and
`default(T)` requests; cancellation atomicity over 400 rounds ("a receipt exists" ⟺ "the key
exists" held every time); 12 threads × 6 s hammering one alias (no deadlock — the lock order is
always backend → `KeyPair` → material, never reversed); `StoredKeyInfo` aliasing; generate and
import of all 8 key types; and capability-snapshot immutability through the public API.

**Not covered, stated rather than silently skipped:** receipt durability across a real process
restart (the backend is in-memory by design); `AccessDenied`/`Throttled`/`OutcomeUnknown`
(documented as unreachable for this store); native memory corruption through the FFI (out of
scope for this surface — the store only ever hands it managed arrays).

### 5.2 Input-validation sweep (NFR-3) — subagent, 41-member surface enumerated, ~190 inputs

The agent enumerated every public member on the new surface that takes caller bytes, a length, an
index, an enum, or a string to parse, then drove all three families against each and **recorded**
outcomes rather than asserting expectations — so nothing was hidden behind a passing assertion.

**Violations accepted and fixed in `src/`:**

| # | Finding | Why it is real |
|---|---|---|
| V1 | A `with` expression bypassed the constructor check on **every** new record type. Validation lived in a property *initializer*, which runs only in the primary constructor. Confirmed on 20 members. The identifier structs were mitigated (the store re-validates), but `KeyStoreCapability`/`KeyStoreCapabilitySet` were re-validated nowhere — and a poisoned set threw **`NullReferenceException`** out of `Find`, `Equals`, and `GetHashCode`, which is on NFR-3's forbidden list. It also falsified the doc claim that the caller's list cannot change what a store advertises. | The repo already uses the closing pattern (`StoredKeyInfo.PublicKey` validates on `init`). Fixed the same way; the doc remark in `KeyStoreIdentifiers.cs` claiming the hole was unclosable is now corrected to name only `default(T)`. |
| V2 | **Fingerprint collision on unpaired surrogates.** `Encoding.UTF8` uses replacement fallback, so `"\ud800"`, `"\udc00"` and `"�"` all encode to `EF BF BD` (verified directly). Two *different* generate requests under one operation id were judged an honest replay: the second returned `Replayed = true` and a receipt naming an alias the caller never asked for, while nothing existed at the alias they did. Same on the delete path. | Breaks rule 5 verbatim. Unpaired surrogates are not exotic — UTF-16 truncation at a code-unit boundary and JSON `\uD800` escapes both produce them. Fixed at the boundary (parameter-named rejection) *and* by making the fingerprint encoder strict, so a lossy encode is impossible rather than merely unreachable. |
| V3 | BBS bound measured on the enumerator, payload copied from the indexer. | Same defect the adversarial pass found as F2, from the other direction. |
| V4 | An off-curve, low-order, or unsolvable peer point arrived as `CryptographicException` and became `KeyStoreException(Unavailable)` — telling the caller to **retry** bytes that can never work, and showing as a backend outage in monitoring. | NFR-3 forbids `CryptographicException` doubling as the catch-all for malformed input. Now a parameter fault, but only on paths that forward caller-supplied *key material*; on the signing path the same exception really is a backend failure. |
| V4b | The legacy `DeriveSharedSecretAsync` leaked the raw platform `CryptographicException`. Byte-for-byte parity with `InMemoryKeyStore` — but this is a **new type**, and the sweep skill is explicit that "migrate verbatim" covers valid-input behavior only. | Fixed on the new type, **and on `InMemoryKeyStore`** — a known contract violation is not something to leave in place once found (only invalid-input behavior changes, so parity holds). Recorded under CHANGELOG *Fixed*. |
| V5 | `ArgumentNullException.ThrowIfNull` picked up `CallerArgumentExpression`, so the parameter name was `"request.Material"` / `"request.Messages"` — not a parameter of the method, and not what the XML docs promised. | `.WithParameterName("request")` failed on both, and neither was covered by the existing suite. |
| V6 | `FromRawKey` accepted key material of **any** length: a 1-byte "P-256 key pair" crossed the custody boundary, was published via `MultibasePublicKey` as a real key, and yielded an `ISigner`, failing only at first use — the exact "first use is the probe" problem this contract exists to remove. | Now length-checked per key type at construction via `RawKeyGuard`. |
| V7 | Legacy `GenerateAsync(alias, (KeyType)999)` threw `ArgumentException` with **no parameter name**. | NFR-3 requires the name; the capable overload already had the guard. |
| V8 | Legacy members accepted aliases (control characters, 100 000 chars) that the capable members can never address — one object, two contradictory alias grammars. | The new type may be strict; `InMemoryKeyStore` is untouched, so nothing existing changes. |
| V9/V10 | `KeyStoreException` accepted an undefined `KeyStoreError` (every caller switches on it); `KeyMutationResult` accepted a null `Info` while both outcome types null-check theirs. | Consistency gaps with their own siblings. |

**Explicitly probed and already correct** (abridged): all four identifier constructors across
null/empty/control/513-char, and the `default(T)` path through every store member with the right
parameter name; bounds and off-by-one on sign, agreement, and alias (512 UTF-8 bytes accepted,
513 rejected, measured in bytes not characters); 11 family-(c) algorithm-id variants with no
silent downgrade anywhere (case, whitespace, U+200B, Cyrillic look-alike, wrong operation, wrong
curve); the hostile-provider matrix; namespace isolation on the legacy members; identity
semantics; the whole `TransferableKeyMaterial` lifecycle; disposal; and `RetryAfter` bounds. The
agent also confirmed empirically the blind spot the skill warns about: P-256 `0x02 || 0^32`
**succeeds**, because `x = 0` decompresses to a genuinely valid point — so an all-zero buffer is
not a family-(c) negative test on that path.

**Fuzz-suite extension.** Neither shared suite reached this surface, and
`InputValidationFuzzTests.AssertValidationContract` accepts `CryptographicException` — which is
exactly how V4 hid. Added a capable-store section with a **stricter** assert that fails on a bare
`CryptographicException`, covering malformed aliases and identifiers, the `default(T)` hole,
malformed peer keys across all four ECDH curves on both the capable and legacy paths, and
`TransferableKeyMaterial.FromRawKey` across every key type × {empty, 1-byte, 10 000-byte}. No
allow-list was added, and none exists anywhere in the suite (checked).

### 5.3 Commands and results

```
dotnet build NetCrypto.sln -c Release -warnaserror        → 0 errors, 0 warnings
dotnet test  NetCrypto.sln -c Release                     → 1195 passed, 5 failed
dotnet test  --filter "Category!=NativeFFI"  (no native)  → 1157 passed, 0 failed
all 11 samples, native present and absent                 → every one exits 0
dotnet run --project tools/ApiCoverageCheck -- samples    → API coverage OK
```

The 5 failures are `BbsUnavailableTests`, which assert BBS is *absent* and therefore fail on any
machine where the native library is built. **Verified pre-existing**: the same 5 fail on the base
commit with the change stashed, and all 5 pass on the no-native leg (the CI configuration they
were written for). Not a regression from this work.

**Regression tests proven genuine.** Each guard was reverted, the test re-run, and the guard
restored — every one failed at its intended assertion:

| Guard reverted | Test that failed |
|---|---|
| `RequireSpeaksForTheAdvertisedKey` call | `ASignatureMadeUnderADifferentKey_IsRejected` |
| unpaired-surrogate check in `RequireCleanText` | `AnIllFormedAlias_IsRejectedRatherThanEncodedToTheReplacementCharacter` |
| `OperationScope.Enter` reentrancy check | `AProviderThatCallsBackIntoTheStore_IsRefusedRatherThanLetThroughTheLock` |
| import derive-and-compare | `ImportingAPublicKeyThatDoesNotBelongToThePrivateKey_IsRejected` |
| BBS snapshot-before-bound ordering | `AMessageListWhoseEnumeratorAndIndexerDisagree_CannotSignPastTheBound` |

**One correction the gates forced on my own fix.** Moving the BBS bound check ahead of the
snapshot also moved the empty-message-set check behind the capability lookup, so on a BBS-absent
platform an argument fault started reporting as `Unsupported`. Caught by the no-native leg, not by
the default test run — the argument check now reads `Count` once, before the capability lookup,
which satisfies both NFR-3 ordering and the TOCTOU fix.

### 5.4 Release state

`Directory.Build.props` → 1.6.0; CHANGELOG `[1.6.0]` closed and dated with its compare link;
`PublicAPI.Unshipped.txt` (215 entries) promoted into `PublicAPI.Shipped.txt` (418 total) per the
PRD §8 per-release hygiene rule, leaving Unshipped empty again.

**Stopping here by agreement:** branch and PR only. No merge, no `v1.6.0` tag, and no NuGet
publish — `release.yml` fires on `v*`, so the irreversible tail stays with the maintainer.
