# PR #27 — Remaining Review Fixes

## Scope decisions

- Keep the existing `feat/capable-keystore-issue-26` branch and PR #27; no merge, tag, release,
  or publish is in scope.
- Address every unresolved actionable item in the re-review at commit `b847152`.
- Preserve the public API surface unless a contract-correct fix proves impossible without a
  change; prefer making the reference store's advertisement honest over weakening NFR-6.
- Treat exceptions by origin, not by broad type: caller-owned material faults remain
  parameter-named argument/disposal faults, while exceptions thrown inside injected generator
  calls become `KeyStoreException(Unavailable)` unless they are the documented invalid-private-key
  `ArgumentException("privateKey")`.

## Plan

- [x] Re-read FR-7b rules 9–11 and enumerate the exact tests for all three remaining findings.
- [x] Make BBS capability advertisement require both an available producing provider and the
  independent in-repo verifier; remove same-provider verification fallback.
- [x] Normalize request-based generate/import generator failures without hiding a genuinely
  consumed/disposed `TransferableKeyMaterial` or misreporting backend cancellation as caller
  cancellation.
- [x] Enforce BBS header/message byte bounds incrementally before copying, and translate an
  inconsistent caller-supplied list/indexer into `ArgumentException("request")`.
- [x] Add focused regressions for no-native BBS advertisement/forgery refusal, generator ODE/OCE/
  internal argument faults, early byte-bound termination, inconsistent list shape, and the exact
  inclusive count limit.
- [x] Prove each regression is genuine against `b847152` (or by reverting the corresponding fix)
  and record the intended failing assertion.
- [x] Run the input-validation sweep and an independent adversarial pass against the built result;
  fix every confirmed finding rather than allow-listing it.
- [x] Run Release build, focused tests, full native-present suite, no-native suite, API coverage,
  and relevant samples; update PRD/CHANGELOG/docs where the corrected contract changes wording.
- [x] Complete the Review section, commit intentionally on the existing branch, push to PR #27,
  and post a concise response with evidence. Do not merge, tag, or publish.

## Acceptance evidence

- A no-native process never advertises BBS merely because the injected producer says it is
  available, and cannot return a producer-certified forgery.
- Generator-originated `ObjectDisposedException`, fabricated `OperationCanceledException`, and
  internal `ArgumentException` surface as `KeyStoreException(Unavailable)` with the original as
  `InnerException`; invalid private-key input remains `ArgumentException("request")` and an
  already-consumed transfer remains `ObjectDisposedException`.
- BBS rejects an oversized header/message before copying it, stops reading the list immediately
  when the cumulative bound is crossed, maps count/indexer inconsistency to
  `ArgumentException("request")`, and accepts exactly 4096 messages where BBS is available.
- No public API diff beyond the already-shipped 1.6.0 surface; all required verification passes.

## Review

Implemented all confirmed re-review fixes and two additional trust-boundary defects found by the
required independent adversarial pass:

- no-native reference stores never advertise BBS merely because an injected producer claims it;
- BBS verification always uses the independent native verifier, and the producer receives a
  separate deep copy so it cannot mutate the verifier's message evidence;
- generator exceptions and unusable outputs are normalized by origin, while the documented
  `ArgumentException("privateKey")` caller fault remains parameter-named `request`;
- generated/imported public and private halves are independently checked before commit;
- BBS count, header, cumulative byte size, and inconsistent list shape reject before excess work.

Verification evidence:

- regression proof: five original tests failed at their intended assertions on `b847152`; the BBS
  mutation regression failed when its deep-copy fix was locally reverted; both mismatched-pair
  tests failed on `b847152`; all pass with the fixes restored;
- Release solution build with warnings as errors: passed;
- hardening suite: 53 passed;
- input-validation/fuzz sweep: 325 passed;
- native-present suite (`Category!=BbsAbsent`): 1221 passed;
- isolated no-native suite (`Category!=NativeFFI`): 1178 passed;
- independent adversarial harness: 30/30 native-present and 25/25 no-native checks passed, with no
  remaining confirmed defect;
- BBS sample and API coverage: passed; `git diff --check`: clean;
- capable-store sample reaches its P-256 section then fails in macOS Apple Crypto module loading;
  the identical failure reproduces at pre-fix `b847152`, so it is an existing local platform
  condition rather than a regression from this patch.

Implementation commit `0b629e3b306f9af81e01c90aebf92e8ef701f3c2` was pushed to PR #27.
The GitHub connector rejected the requested update with HTTP 403; the authenticated `gh pr review`
fallback posted the full evidence as a `COMMENTED` review on the current head.
