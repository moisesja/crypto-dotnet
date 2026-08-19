# PR #29 — address the non-approving review (4 blockers + 2 cleanups)

Review: moisesja, 2026-08-19T02:40Z ("would not merge yet"). Assessment of each claim first;
fixes second. Branch: `fix/transferable-consume-public-issue-28`.

## Assessment

- **B1 — `Dispose`/`Discard` during a live read leaves the object observably un-disposed.**
  VALID. The `_reading` defer branch returns without latching `_consumed`, so until the reader
  finishes: `IsConsumed == false`, `KeyType`/`PublicKey` still succeed, and a second `Consume`
  throws `InvalidOperationException` where the docs promise `ObjectDisposedException`. The doc
  comment's claim ("by the time this call's effect can be observed, the state already holds") is
  false for exactly the parked-reader window the reviewer reproduced. Fix as suggested: **latch
  the terminal state before returning; defer only the physical wipe** to the in-flight read's
  `finally` (wiping mid-read is still forbidden — that was the all-zero-key bug).
- **B2 — deadlock regression tests can hang CI.** VALID. The tests use foreground `Thread`s; on
  a regression the bounded join *asserts* but the deadlocked foreground threads keep the
  testhost process alive at exit. Fix: `IsBackground = true` everywhere in those tests, and
  capture worker exceptions instead of throwing on raw threads.
- **B3 — CHANGELOG compare links stale.** VALID; already fixed in the working tree (uncommitted
  at review time). Commits with this batch. (PRD "per-release hygiene" §, netcrypto-prd.md:868.)
- **B4 — external "replay" test is not a replay.** VALID. `WrappingExternalKeyStore` keyed
  replay off duplicate alias and the test used two different `KeyOperationId`s — teaching the
  wrong contract (identity is `(NamespaceId, Kind, OperationId)`). Fix: minimal per-store
  mutation ledger keyed by operation id with a value-tuple fingerprint (alias, keyType,
  publicKey — never the private half): same id + same fingerprint → `Replayed:true` +
  `Discard()` unread; same id + different fingerprint → `KeyStoreException(IdempotencyConflict)`
  with material left usable; duplicate alias + fresh id → refused before the read, material
  usable. Test reuses the SAME operation id and covers the conflict case.
- **C1 — `ExposesNoReadPathForPrivateMaterial` name/claim stale.** VALID. Reframe: the type has
  no getter/format/export member; `Consume` is the one sanctioned, delegate-mediated read; assert
  both halves explicitly.
- **C2 — hostile-reader sweep overclaims NFR-3.** VALID. Reader-thrown exceptions propagate
  unmodified BY DESIGN (they originate in the store's own code, not NetCrypto's input
  validation; the external tests rely on unmodified propagation). Reframe the test: NetCrypto's
  own refusals stay in contract; reader-originated exceptions propagate as-is (add a
  `FormatException` case asserting same-instance propagation); the wipe holds on every path.
  State the propagation rule in `Consume`'s XML docs.

## Fixes
- [x] F1 `Dispose`: latch `_consumed` immediately in the `_reading` branch; defer only the wipe.
      Update `Dispose`/`Discard`/`Consume` XML docs + CHANGELOG wording to latch-now/wipe-later.
- [x] F2 Regression test: parked reader → `Dispose` from another thread → assert, BEFORE the
      reader is released: `IsConsumed == true`, metadata throws ODE, new `Consume` throws ODE;
      after release: buffer wiped. Prove genuine (revert F1 → fails at the parked assertions).
- [x] F3 `ConsumeConcurrencyTests`: background threads + captured worker exceptions.
- [x] F4 `WrappingExternalKeyStore` idempotency ledger + corrected replay/conflict tests.
- [x] F5 C1 + C2 test reframes; `Consume` XML doc sentence on reader-exception propagation.
- [x] F6 Full verify: build -warnaserror, suite under CI filter, samples, coverage.
- [ ] F7 Commit (with B3's CHANGELOG links), push to PR #29, reply to the review point-by-point.

## Review

All four blockers and both cleanups addressed; every reviewer claim reproduced or verified
before fixing — none was argued down.

- **B1** `Dispose`/`Discard` now latch `_consumed` immediately even against a live read; only
  the physical wipe defers to the reader's `finally`. New regression
  `DisposeDuringALiveRead_LatchesImmediately_AndDefersOnlyTheWipe` asserts, with the reader
  still parked: `IsConsumed == true`, `KeyType`/`PublicKey`/`Consume` all throw
  `ObjectDisposedException`; after release the read still observed the true bytes and the buffer
  is wiped. **Revert-and-fail proven:** with the latch back below the defer branch the test
  fails at `Expected material.IsConsumed to be True … but found False`. Docs updated
  (Dispose/Discard/Consume XML, CHANGELOG) to latch-now/wipe-later wording.
- **B2** All threads in `ConsumeConcurrencyTests` are background (`IsBackground = true`) with
  worker exceptions captured into a queue and re-asserted on the test thread — a regression
  fails its bounded join and the testhost can still exit.
- **B3** CHANGELOG compare links — fixed and committed by the maintainer as `5fbc785`; wording
  of the Fixed entry updated here to match B1's semantics.
- **B4** `WrappingExternalKeyStore` now keeps a mutation ledger keyed by `KeyOperationId` with a
  value-tuple fingerprint (alias, keyType, publicKey hex — never the private half): same id +
  same fingerprint → `Replayed:true` + `Discard()` unread + original receipt; same id +
  different fingerprint → `KeyStoreException(IdempotencyConflict)`, material left usable;
  duplicate alias + fresh id → refused before the read, material usable. Replay test now reuses
  the SAME operation id; conflict and duplicate-alias cases added.
- **C1** Test renamed `TheOnlyReadPathIsConsume_AndThereIsNoGetterFormatOrExportSurface`; keeps
  the no-getter/format/export name screen and adds a closed-list equivalence over the full
  public surface, so `Consume`/`Discard` are asserted as the one sanctioned pair and any new
  read-shaped member fails the test.
- **C2** Hostile-reader sweep renamed and split into the true contract: NetCrypto's own refusals
  are documented types; reader-thrown exceptions (including the reviewer's `FormatException`
  probe) propagate **same-instance, unmodified** — asserted with `BeSameAs`; spend+wipe hold on
  every path. The propagation rule is now stated in `Consume`'s XML remarks.

Verification: `-warnaserror` clean; full suite under the CI filter **1230 + 18 = 1248 passed,
0 failed**; all 11 samples exit 0; ApiCoverageCheck OK.

