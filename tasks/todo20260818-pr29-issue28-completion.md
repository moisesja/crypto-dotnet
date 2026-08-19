# Complete PR #29 / issue #28 — publish `TransferableKeyMaterial`'s single-read surface

Branch: `fix/transferable-consume-public-issue-28` (already exists, clean, pushed)
Inherited: commits `c040991` (the widening) + `514b8a8` (1.7.0 release prep)
Governing requirement: `netcrypto-prd.md` FR-7b rule **7** (import transfers ownership exactly
once), rule **14** (a callback must not re-enter), NFR-3 (input validation), FR-17 (samples
cover every public name), FR-18 (zeroization).

## Verification of the inherited work (done first, per the resume rule)

| Check | Result |
|---|---|
| `dotnet build NetCrypto.sln -c Release` | 0 warnings / 0 errors |
| `dotnet test NetCrypto.sln -c Release --no-build` | 1221 passed, **5 failed** |
| — the 5 failures | all `BbsUnavailableTests`, `[Trait("Category","BbsAbsent")]`, which CI excludes via `--filter "Category!=BbsAbsent"` when the native lib is present. Pre-existing, unrelated. The PR body used an ad-hoc `FullyQualifiedName!~` filter instead of the CI filter. |
| `dotnet run --project tools/ApiCoverageCheck -- samples` | **FAILS — 2 uncovered names** |

## Gaps found in PR #29

- **G1 — CI is red (FR-17).** `KeyMaterialReader` and `TransferableKeyMaterial.Discard` appear
  nowhere under `samples/`. `Consume` passes only by accident: the check is a substring match
  and `IsConsumed` contains "Consume". The PR's "Validation" section never ran this step.
- **G2 — Zero tests.** 34 added lines, no test. The issue's acceptance sketch is explicitly
  "an external assembly **not on the IVT list**"; `NetCrypto.Tests` *is* on that list, so no
  test that could live in the current suite proves the fix. Nothing in the repo would catch a
  regression back to `internal`.
- **G3 — Re-entrancy hole, newly reachable from outside (security-relevant).** `Consume` invokes
  the caller's delegate while holding a **reentrant** `Monitor`, and latches `_consumed` only in
  the `finally`. A reader that calls `Consume` again on the same instance on the same thread
  passes the disposed check, drives `ReadCount` to **2**, and on the inner unwind zeroizes
  `_privateKey`/`_publicKey` **while the outer reader's spans still alias them** — so the outer
  store ingests an all-zero key. This breaks the type's headline invariant and is the same class
  of bug PRD rule 14 already forbids (`CapableInMemoryKeyStore.OperationScope`,
  `CapableInMemoryKeyStore.cs:854-875`). Unreachable while `Consume` was `internal` (sole caller
  was the in-assembly store); publishing it makes an untrusted delegate the caller.
- **G4 — Stale / incomplete docs.** The class remark still says the secret "is read exactly once
  through an **internal** accessor" (`TransferableKeyMaterial.cs:38-39`). The newly public
  `Consume`/`Discard` carry no `<exception>` tags, unlike every other public member here.
- **G5 — Threat-model delta unstated.** "No export surface is added" holds for the two intended
  parties, but the real delta is that any code holding a live `TransferableKeyMaterial` — or the
  `KeyImportRequest` carrying it, through a DI decorator or logging middleware — can now read the
  secret. That is a bearer-secret rule that belongs in the contract text.
- **G6 — PRD contradicts the shipped surface.** `netcrypto-prd.md:211` and rule 7 (`:272`) still
  say "**no** private-key read … surface". The PRD is the source of truth.
- **G7 — Neither gate run.** No `adversarial-pass`, no `input-validation-sweep`.

## Plan

### A. Source fix
- [x] A1 `TransferableKeyMaterial.Consume` — refuse same-thread re-entry with
      `InvalidOperationException`, mirroring `CapableInMemoryKeyStore.OperationScope`'s wording
      and rationale (G3).
- [x] A2 `Dispose()` called re-entrantly from inside a reader must **not** wipe mid-read; it
      defers to the in-flight `Consume`'s `finally`, which wipes and latches anyway. Keeps
      `Dispose`'s documented idempotent/never-throws contract exactly, and the observable end
      state is unchanged (G3). `Discard()` inherits this.

### B. Tests
- [x] B1 New project `tests/NetCrypto.ExternalStore.Tests` — **deliberately not** matching the
      `InternalsVisibleTo("NetCrypto.Tests")` name, referencing `NetCrypto` by ProjectReference.
      Its existence is the compile-time proof; added to `NetCrypto.sln` so CI runs it.
- [x] B2 In it: a minimal out-of-assembly `ICapableKeyStore` whose `ImportAsync` performs the
      routed import through `Consume` (the BYOK-wrap shape from the issue). Asserts the issue's
      three acceptance points: read exactly once, `IsConsumed == true` after, every later read
      `ObjectDisposedException`; plus `Discard()` destroying an unread owner.
- [x] B3 Re-entrancy regression, external delegate (G3): re-entrant `Consume` throws
      `InvalidOperationException`; the outer reader still sees the true key bytes, not zeros.
- [x] B4 In-assembly counterpart in `NetCrypto.Tests` asserting `ReadCount` stays 1 under an
      attempted re-entry (uses the internal counter the external project cannot see).
- [x] B5 `Dispose`-inside-reader test: the outer read still returns real bytes; the instance is
      consumed and zeroized afterwards.
- [x] B6 **Prove B3/B4/B5 genuine** — revert A1/A2, confirm they fail at the intended assertion,
      restore.

### C. Sample (fixes CI, and is itself an out-of-assembly use)
- [x] C1 Extend `samples/NetCrypto.Samples.CapableKeyStore/Program.cs` §5 with the external-store
      acceptance path: an explicit `KeyMaterialReader<T>`, a `Consume` call, and a `Discard()`
      on the replay path. Restores FR-17 coverage for all three names (G1).
- [x] C2 `samples/README.md` line for the sample mentions the store-side acceptance path.

### D. Docs / contract
- [x] D1 `TransferableKeyMaterial.cs` — drop "internal accessor"; add `<exception>` tags to
      `Consume`/`Discard`; state the bearer-secret rule and the no-re-entry rule (G4, G5).
- [x] D2 `netcrypto-prd.md` — rule 7 and the shape bullet at `:211`: the read path is public and
      is the store-side acceptance path; no getter/format/export surface still holds; add the
      re-entry refusal (G5, G6).
- [x] D3 `README.md` rule 7 — same one-line correction if it overstates.
- [x] D4 `CHANGELOG.md` 1.7.0 — note the re-entrancy guard alongside the widening; drop the
      unqualified "semantics are unchanged" for an accurate statement.
- [x] D5 `PublicAPI.Shipped.txt` — no new entries expected (the guard adds no member); re-verify
      RS0016/RS0017 clean.

### E. Gates
- [x] E1 `adversarial-pass` skill against the new public surface.
- [x] E2 `input-validation-sweep` skill against `Consume`/`Discard`/`FromRawKey`/`FromKeyPair`.
- [x] E3 Fix anything either turns up in `src/` (never an allow-list entry).

### F. Verify & land
- [x] F1 `dotnet build NetCrypto.sln -c Release -warnaserror`
- [x] F2 `dotnet test NetCrypto.sln -c Release --no-build --filter "Category!=BbsAbsent"` (the CI filter)
- [x] F3 every sample runs and exits 0
- [x] F4 `dotnet run --project tools/ApiCoverageCheck -- samples` → OK
- [ ] F5 Commit on this branch, push, update the PR body with real validation output.

## Scope decisions
- **Do the re-entrancy fix in this PR, not a follow-up.** This PR is what makes the hole
  reachable; shipping 1.7.0 with a publicly reachable invariant break and fixing it in 1.7.1
  would mean knowingly releasing the defect.
- **A new test project rather than reflection assertions.** `IsPublic` reflection inside
  `NetCrypto.Tests` would pass even if the members were later re-narrowed behind a wider IVT;
  only a non-IVT assembly that *compiles* against them proves the issue's acceptance criterion.
- **Version stays 1.7.0.** The guard adds no public member and the widening is already the
  minor bump; nothing shipped yet.
- **Out of scope:** the 5 pre-existing `BbsAbsent` local failures (environment, not this change).

## Acceptance evidence
Filled in in the Review section: build/test/sample/coverage output, the revert-and-fail proof
for B6, and both gate reports.

## Review

### What was wrong with PR #29 as inherited
Two commits (`c040991` widening + `514b8a8` release prep) made the three members public and
bumped to 1.7.0, but: **CI was red** (FR-17 coverage: `KeyMaterialReader` and `Discard`
uncovered), there were **zero tests** for the out-of-assembly path the issue's acceptance
sketch demands, **neither gate was run**, and the widening exposed a **latent invariant break**
in `Consume` that was unreachable while it was `internal`.

### Source changes
- `Consume` **runs the reader outside `_gate`** (claims the read under the lock, releases,
  invokes the reader, re-acquires only to wipe+latch). Fixes the adversarial deadlock (below).
- Re-entrancy / concurrent-read guard: `_reading` set under `_gate`; a nested or concurrent
  `Consume` while a read is live is refused with `InvalidOperationException`; a `Dispose`/
  `Discard` during a read defers its wipe to the reader's `finally`.
- Docs: bearer-secret rule, retained-pointer hazard, `<exception>` tags, lock-release contract.

### Adversarial pass (independent subagent, executed exploit code)
- **34 attacks, 11 findings, 34 non-findings.** The `_reading` guard survived every re-entry,
  span-escape (captured pointer / `Unsafe.As` / `MemoryMarshal` write-through all see zeros),
  covariance, and 136 `FromRawKey` input probes (all parameter-named `ArgumentException`, no
  leaked backend/platform type).
- **F1–F4 (fixed): the reader ran under `_gate`.** Reproduced a real ABBA deadlock
  (`scratchpad/f2repro`) — a store reader taking its own lock while another thread disposes
  under that lock — which **left the secret un-wiped in the pinned buffer for the process
  lifetime**, and also let an untrusted reader block `IsConsumed`/`Dispose`/the finalizer
  thread. Root cause: foreign code invoked under a private lock. Fixed by releasing the lock
  across the reader. Regression tests in `ConsumeConcurrencyTests` fail (via bounded waits) on
  the pre-fix body and pass after — verified by reverting `Consume` in place.
- **F5 (doc, fixed):** the delegate remark implied the wipe made a retained span harmless;
  reworded — a retained pointer later reads other materials' secrets via pinned-heap address
  reuse, so retaining any pointer/reference is a reader bug regardless of the wipe.
- **F6/F7/F8 argued down (out of #28 scope or WAI):**
  - F6 (replay of a mismatched `(pub_A, priv_B)` under a reused operation id returns
    `Replayed:true`): the replay path must **not read** the private half (rule 7), so it cannot
    distinguish `priv_B` from `priv_A`; a valid pair with a fresh id is still derive-checked and
    a lying pair rejected. Requires the caller to reuse an idempotency key with a public key
    matching a prior import — self-inflicted, and it cannot substitute a stored key. Reference-
    store idempotency, not the #28 surface.
  - F7 (`ImportAsync` duplicate alias throws bare `InvalidOperationException`): pre-existing from
    #26; the suite already treats it as the documented duplicate-alias signal inherited from
    `InMemoryKeyStore`. Out of scope.
  - F8 (multicast `KeyMaterialReader` fans the secret to its combined bodies; `ReadCount==1`):
    a multicast delegate is one reader the caller themselves combined — equivalent to a single
    body doing three things — so it is one read event, not a second read. `ReadCount` internal
    is WAI per the issue.
- **Follow-up flagged (not in this PR):** `KeyPair.WithPrivateKey<T>` holds its own `_gate`
  across its callback the same way. It is public but not part of the #28 surface; recommend a
  separate issue.

### Adversarial re-check of the lock-release fix (second independent subagent)
Because the fix rewrote security-critical concurrency, a focused re-check attacked the *new*
design specifically. **No security defect** across ~250k contended attempts (8–16-thread
stampedes, barrier-synchronized entry, 14-way chaos, each replayed twice): zero double-reads
(`successCount` always exactly 1, `ReadCount` never > 1), no un-wiped buffer on any exit path,
no torn/half-zeroed `PublicKey`, no stuck `_reading`, and the ABBA deadlock confirmed gone. Two
non-vulnerability notes: (1) the fix was uncommitted at re-check time — now committed; (2)
`ObjectDisposedException` derives from `InvalidOperationException`, so a caller catching `IOE`
also catches the spent case — addressed with a doc note (both refusals are terminal, so this is
a clarity fix, not a new exception type). The `Thread.Abort`-between-claim-and-try window it
raised is unreachable on .NET 10 (`Thread.Abort` throws `PlatformNotSupportedException`; no
allocation/OOM point in the window) — verified by the subagent.

### Input-validation sweep (NFR-3)
Added `TransferableKeyMaterial_HostileReader_StaysInContractAndAlwaysWipes` (family-(c): a
well-formed but hostile reader) — six readers (throws / re-enters / disposes / discards /
returns the span as an array / re-enters-then-throws) each assert only contract exception types
escape and the pinned buffer is wiped. `FromRawKey` fuzz matrix already covered families (a)/(b).

### Regression genuineness (revert-and-fail, all restored)
- Re-entrancy: pre-fix `ReadCount` reached **2** and the outer read observed **32 zero bytes**
  (probe + `ConsumeReentrancyTests`/in-assembly `ReadCount` tests fail at the intended assertion).
- Deadlock: pre-fix `ConsumeConcurrencyTests` (3 of 4) fail via their bounded joins; `f2repro`
  console prints `DEADLOCK … secret left un-wiped`.

### Commands and results (this machine)
- `dotnet build NetCrypto.sln -c Release -warnaserror` → **0 warnings, 0 errors** (RS0016/RS0017
  clean; PublicAPI baseline holds — the guard added no member).
- `dotnet test NetCrypto.sln -c Release --no-build --filter "Category!=BbsAbsent"` (the CI filter)
  → **NetCrypto.Tests 1229 passed; NetCrypto.ExternalStore.Tests 15 passed; 0 failed.**
- All 11 samples exit 0; `ApiCoverageCheck` → **API coverage OK**.
- The 5 local `BbsAbsent` failures are pre-existing and environment-only (the no-native leg
  asserts `IsAvailable==false` while this machine has the native lib); excluded by the CI filter.

### Scope decisions honored
Re-entrancy AND deadlock fixed in this PR (this PR is what makes both reachable); new non-IVT
test project is the compile-time proof of the acceptance criterion; version stays 1.7.0.

