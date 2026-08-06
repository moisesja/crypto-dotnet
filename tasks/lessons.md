# Lessons

## L1 — Verbatim migration silently carries latent backend-crash bugs (NFR violations)

**Context:** NetCrypto FR-1…FR-9 were migrated verbatim from net-did under a strict
behavior-parity rule. The adversarial review found that secp256k1 `Sign`/`FromPrivateKey`
crashed with `IndexOutOfRangeException` on sub-32-byte keys (NBitcoin indexes a 32-byte span)
and the BBS provider threw `NullReferenceException` on null lists — both direct violations of
the PRD's NFR-3 ("no public method can be made to throw IndexOutOfRangeException/
NullReferenceException from bad input").

**Rule:** "Migrate verbatim" applies to *valid-input behavior, wire formats, names, and
exception types* — it does NOT exempt the public surface from the project's non-functional
acceptance criteria. When a parity rule and an NFR collide on *invalid* input, the NFR wins:
add the input guard. A guard that converts a crash into the contractually-required
`ArgumentException` changes no valid-input behavior, so parity (and the migrated tests) hold.

**How to apply:** After any verbatim migration, run a fuzz-lite pass (null/empty/oversized
across the whole surface) *before* declaring the phase done. Treat every IOOR/NRE/Overflow as a
defect to fix, never to pin. The fuzz test author here had pinned the secp256k1 crash in a
`KnownBackendDeviations` list to keep the suite green — that hides the bug instead of failing on
it. A test that documents a contract violation as "tolerated" is a red flag; the suite must fail
on NFR breaches, not accommodate them.

## L2 — Verify size/buffer formulas empirically, not from a code comment

**Context:** `DefaultBbsCryptoProvider.DeriveProof` allocated the proof buffer from a comment
formula `144 + 32·(undisclosed+1)`; the true BLS12-381-SHA-256 proof size is `272 + 32·undisclosed`.
A 512-byte floor masked the 96-byte shortfall for small reveals, so the existing tests (3 messages,
reveal 2) passed — but ≥8 undisclosed messages threw `CryptographicException`. The defect rode
along through migration because no test exercised a large undisclosed count.

**Rule:** When an FFI/native call writes its true output length back (here `proof_out_len`), size
the managed buffer generously off an upper bound (total message count) rather than a hand-derived
floor — robust to spec/library drift. Confirm any size formula by running the real primitive
across boundary inputs before trusting it.

**How to apply:** For variable-length crypto outputs, add a regression test at the *large* end of
the parameter space (here ≥10 messages revealing 1), not just the happy-path small case.

## L3 — NFR-3 "fuzz-lite" must use malformed-but-present inputs, not just null/zero

**Context:** The 2026-06-11 security review found the *same* NFR-3 crash-class as L1 living in
three more public methods the original fuzz pass missed: `JwkConverter.ExtractPublicKey` leaked a
raw `FormatException` on bad base64url, `KeyTypeExtensions.NormalizeToCompressed(null)` threw
`NullReferenceException`, and `ConcatKdf.DeriveKey` threw `OverflowException` for a huge
`keyDataLen`. The existing `InputValidationFuzzTests` only fired null and all-zero buffers, so it
never exercised: a structurally-valid base64 string that is not valid base64url; a point whose
coordinate is on-curve by *value* but left-zero-trimmed in *length*; an off-curve-but-parseable
NIST point (which made `Verify` throw instead of returning `false`); or an oversized length
parameter. Zero buffers are a special blind spot: for P-256, x=0 decompresses to a *valid* point,
so a zero-filled "bad key" silently took the happy path.

**Rule:** "Validate the whole surface against bad input" means three input *families*, not one:
(a) absent — null/empty; (b) wrong-shape — wrong length, oversized, non-multiple; (c)
**structurally-valid-but-semantically-wrong** — bad base64url, off-curve points that still parse,
left-trimmed coordinates, high-S signatures, indices past the count. Family (c) is where the real
defects hide, because (a) and (b) usually fail fast in obvious ways. Every public method that
parses caller bytes needs at least one family-(c) negative test.

**How to apply:** When auditing a parse/import/convert method, ask "what input passes the cheap
length/null checks but breaks the *next* layer?" and write that test. Forbidden leaked exception
types are not just `IOOR`/`NRE` — also `FormatException`, `OverflowException`,
`KeyNotFoundException`, and any backend exception; all must become `ArgumentException`/
`ArgumentNullException` (or a documented `false` for verify-style methods). Widen the shared fuzz
test to feed non-zero random and "valid-encoding-of-invalid-value" buffers, not only zeros.

## L4 — AGENTS.md mandates an adversarial agent on generated code; run it before saying "done"

**Context:** For issue #2 (expose the BBS `header`) I implemented, ran the happy-path + a few
negative tests, and reported the task complete — without launching the adversarial exploitation
agent that AGENTS.md §2 ("Always use adversarial agents to attempt to exploit the code that is
being generated") requires. The user had to ask "Did you run an adversarial exploitation per
AGENTS.md?" The agent I then ran executed 24 exploit attempts (header-strip/mandatory-drop,
header↔ph aliasing, empty-vs-1-byte boundary, FFI mid-buffer-slice marshalling, asymmetric
argument-order to catch a header/ph slot swap, 1 MB and embedded-null headers) and found no
exploit — but the point is the check is not optional and is most valuable on **security-relevant**
changes, which is exactly when it's tempting to skip because the unit tests are green.

**Rule:** A change is not "done" until an independent adversarial agent has tried to break it and
reported. My own round-trip tests prove the feature *works*; they do not prove it *can't be
abused*. Especially for crypto/auth/binding code, the adversarial pass is part of the definition
of done, not a follow-up. Bonus: it caught that BBS `proof_gen` does not pre-validate the
signature (success ≠ valid proof; the gate is `VerifyProof`) — a real semantic the happy-path
tests obscured.

**How to apply:** After implementing any security-relevant change and before declaring completion,
launch an adversarial subagent that WRITES AND RUNS exploit code (not just reasons) against the
built artifact, with an explicit "your job is to break this, report every weakness" framing and a
concrete attack list. For binding/commitment properties, always include an *asymmetric* test
(different-length inputs) so a silent argument-order swap can't pass via symmetry.

## L5 — A permissive test contract hides real gaps; "passes the fuzz suite" ≠ "clean errors"

**Context:** A security review (preview.3) flagged that wrong-length raw keys leaked
`System.FormatException` (NSec), `Nethermind.Crypto.Bls+BlsException`, and macOS
`AppleCommonCryptoCryptographicException` from `DefaultCryptoProvider`/`DefaultKeyGenerator` instead
of a parameter-named `ArgumentException`. Two reasons it survived: (a) the fuzz-lite assertion
tolerated `CryptographicException` as "in contract," so the EC private-key path leaking a *platform
crypto exception* on a wrong-length key passed the suite even though NFR-3's normative text demands
a parameter-named `ArgumentException` "before any crypto operation"; (b) the NSec/BLS
`FormatException`/`BlsException` leaks were *pinned* in a `KnownBackendDeviations` allow-list (the
exact red flag L1 named) so the suite stayed green while the gap stayed open. The fix was an
up-front length guard (`RawKeyGuard.RequireLength`) at every backend hand-off, plus a try/catch that
converts BLS's value-validity `BlsException` to `ArgumentException`, plus deleting the allow-list
entirely so any non-contract exception now fails.

**Rule:** When a test's pass condition is broad ("throws any of A/B/C, or is pinned"), it certifies
far less than it appears. A wrong-length input is a *caller bug* and must produce a clear,
parameter-named `ArgumentException` — `CryptographicException` (even a platform subclass) is
reserved for genuine crypto failures and must NOT double as the catch-all for malformed input.
Reflect the strict bar in BOTH the assertion (no allow-list; non-contract exception ⇒ fail) and the
PRD AC, so the contract can't quietly relax again.

**How to apply:** For every public method that forwards caller bytes to a third-party/native/platform
backend, validate length (and other cheap invariants) *before* the hand-off and map any residual
backend exception to `ArgumentException(paramName)`. Never pin a backend-exception deviation to go
green — fix src. Write the assertion as `WithParameterName(...)`, not merely "threw something in a
set." Probe each backend's actual failure type on bad input on every supported OS (the macOS EC
exception differs from Windows/Linux), since "in contract on my machine" can hide a leak elsewhere.

## L6 — "It's just a thin wrapper/delegation" is NOT a license to skip the adversarial pass

**Context:** Implementing the NetCrypto 1.1.0 issues (#10 on-curve doc, #11 IKeyStore ECDH, #12
base64url + AEAD constants), I shipped all three PRs and declared them done WITHOUT running the
adversarial agents CLAUDE.md §2 and lesson L4 mandate. For #11 I explicitly rationalized the
omission — "the new path delegates to the existing, already-tested DeriveSharedSecret, it adds no
new crypto" — and skipped the exploit pass on that basis. The user caught it ("Did you ever run
adversary agents? Did you follow CLAUDE.md?"). When I then ran three adversarial agents (write-and-run
exploit code, per L4), the "thin" code yielded two real LOW findings: `Base64Url.Decode` silently
stripped ASCII whitespace (multiple wire forms → same bytes, contradicting the documented "throws on
invalid input" and the canonical-codec goal), and wrong-length NIST EC peer keys leaked a platform
`CryptographicException` instead of the NFR-3 parameter-named `ArgumentException` (a gap my own #11
XML doc had promised was closed). Neither was exploitable, but both were genuine contract defects in
exactly the code I'd dismissed as too trivial to attack.

**Rule:** "Thin wrapper", "just delegates", "no new crypto" is precisely the rationalization L4 warns
against — it describes where the NEW surface is, not where the RISK is. A wrapper inherits the
backend's *exception* and *canonicalization* behavior, which is part of the public contract and is
frequently wrong at the seam (whitespace stripping, opaque backend exception types, length confusion).
The adversarial pass is part of the definition of done for ANY security-relevant change, including
delegations and codecs — not a follow-up, and never waived by self-assessed triviality. Run it BEFORE
declaring done, not after the user asks.

**How to apply:** For every security-relevant change — including thin wrappers, delegations, codecs,
and "just exposing a constant" — launch adversarial subagent(s) that WRITE AND RUN exploit code
against the built artifact, with an explicit "break this, report every weakness" framing and a
concrete attack list, BEFORE saying it's done. Especially probe the seam the wrapper delegates across:
exception TYPE on malformed/wrong-length input (must be parameter-named `ArgumentException`, never a
leaked backend/platform exception), and input CANONICALIZATION (does the codec accept multiple textual
forms for the same bytes?). If you catch yourself writing "it's just a thin X so I'll skip the
adversarial pass," that sentence is the trigger to run it, not skip it. See [[L4]], [[L5]].

## L7 — "Go" authorizes the goal, not skipping the plan-approval checkpoint

**Context:** For issue #21 ("deploy this single issue as version 1.4.0 … Go") I wrote the plan
file and immediately started implementing on a branch without checking in. The user interrupted:
"How come you aren't giving me a plan to approve?" The task-management workflow is explicit —
"Verify Plan: Check in before starting implementation" — and a release task is exactly the case
where the checkpoint matters most, because the tail end (merge, tag, NuGet publish) is
irreversible and outward-facing.

**Rule:** An energetic go-ahead in the task statement ("Go", "just do it") authorizes the
*outcome*, not the omission of the plan-approval step. The plan check-in is cheap; an
irreversible release built on an unapproved plan is not. Present the plan first, get the nod,
then run autonomously to the end.

**How to apply:** For any non-trivial task, and unconditionally for any task that ends in a
publish/release/deploy: write `tasks/todo{timestamp}.md`, then STOP and present the plan for
approval before the first implementation edit. Only skip the check-in when the user has
approved the plan itself, not merely the goal.

## L8 — A direct PR-review command authorizes execution; do not turn it into a plan gate

**Context:** The user explicitly asked to inspect a newly opened pull request and post either
specific concerns or an approval. I created the required task plan, but then stopped and asked
the user to approve that plan. The user corrected this: the request was already an instruction
to perform the review and publish the result, not an invitation to negotiate the workflow.

**Rule:** For a read-and-review task whose requested outcome is an ordinary PR review comment,
write and maintain the repository's task plan without introducing an extra approval gate. The
plan checkpoint is for implementation/release decisions where the plan materially affects what
will be built or published; it must not block routine execution the user already authorized.

**How to apply:** When the user says to review a PR and post the result, identify the PR, inspect
it, and submit the review in the same run. Only stop for clarification when the repository or PR
cannot be resolved safely, or when the requested external action is genuinely ambiguous.

## L9 — Adversarial coverage for a delegation/boundary type must probe state-mutation-under-a-live-handle and full backend-output passthrough, not just input guards

**Context:** For issue #21 I ran an adversarial pass that reported "57 exploit tests, zero
findings" and declared the code sound. Two human reviews and a second, deeper adversarial pass
then found three real defects the first pass missed, all on the `KeyStoreSigner`/`IKeyStore`
seam: (1) **alias rebinding** — delete an alias, recreate it with a new key, and an old signer
still signs with the new key while advertising the old public key (identity confusion); (2) a
**malformed store output** (`RecoverableSignature([0x01], 27)`) passed straight through the
non-nullable, contractually-64-byte API; (3) the **DIM default** threw `NotSupportedException`
instead of the documented parameter-named `ArgumentException("digest32")` on a bad digest length.
The first pass had tested input guards exhaustively (lengths, null, wrong key type, disposed) and
even a bogus store — but only to confirm the *length guard fires first*, never the
*valid-digest passthrough* of garbage; and it tested import-under-two-aliases but never
delete-then-recreate.

**Rule:** For a type that DELEGATES to mutable external state (a store, an HSM, a provider) behind
a handle that caches metadata (here `KeyStoreSigner` caches `PublicKey`/`KeyType` at
construction), the adversarial pass must cover three families the input-guard sweep does not:
(a) **state mutation under a live handle** — rebind/delete/recreate the delegated-to entity, then
use the stale handle, and check the handle's advertised identity still matches what it produces;
(b) **hostile/buggy backend output** — a backend that returns structurally-valid-looking but
wrong or malformed results for a *valid* input, verifying the wrapper validates OUTPUT
symmetrically to how it validates INPUT (L6's seam, on the return path); (c) **advertised-vs-produced
consistency** — for any type that both advertises an identity and produces identity-bearing output
(a recoverable signature literally encodes its signer), assert the two agree before returning.
"Zero findings" from a pass that only fed bad inputs certifies input handling, not boundary
integrity. See [[L6]], [[L4]].

**How to apply:** When the change wraps or delegates across a trust boundary, add to the
adversarial brief an explicit checklist: mutate the backing state mid-life (delete/recreate/rebind)
and reuse the handle; return malformed AND wrong-but-valid output from a test-double backend for a
good input; and assert `recover(output) == advertised identity`. Only after those run may the pass
claim the seam is sound. The fix pattern for (a)+(c) here was a recover-and-compare guard at the
wrapper boundary; for (b), structural validation of the backend's result before returning it.

The second pass exposed the same rule on mutable buffers in both directions. A wrapper that caches
identity bytes must clone constructor input and keep its internal snapshot separate from any memory
it exposes. A wrapper that sends caller bytes to an arbitrary provider needs two copies when it
must verify the original request after the provider returns: one private verification snapshot and
one provider copy. Passing the verification snapshot itself is insufficient because a provider can
recover and mutate the backing array of `ReadOnlyMemory<byte>`.

## L10 — Issue work belongs on a branch from the first edit, not left uncommitted on `main`

**Context:** Issue #23 was picked up by an earlier agent that implemented the fix, the tests, and
all four documentation surfaces — then stopped without ever committing. The entire change sat as
unstaged modifications on `main`: seven modified tracked files plus an untracked plan file. On
resuming, the user's first correction was "put this work on its own branch." The work itself was
sound and complete; the only thing wrong was where it lived. Uncommitted work on `main` is the
worst of both worlds — it is invisible to `git log`, it is lost to any `git checkout`/`git stash`
mistake, it cannot be pushed or reviewed, and it silently contaminates the next unrelated task
that starts from what looks like a clean `main`.

**Rule:** Create the feature branch **before the first edit** of any issue/feature task, not at
commit time and never as a cleanup step. Branching is free and is the only cheap moment; the cost
of not branching is paid entirely by whoever picks the work up next. Equally: an implementation is
not "finished" at the last passing test — it is finished when it is committed on a named branch.
Leaving verified work uncommitted throws away the verification, because the next agent cannot tell
completed work from an abandoned half-edit without re-deriving all of it. See [[L4]].

**How to apply:** At the start of any task tied to an issue, run
`git checkout -b <type>/<slug>-issue-<n>` as the first tool call after reading the issue, matching
the repo's existing naming (`feat/`, `fix/`, `docs/`). When *resuming* someone else's unfinished
task, check `git status` and `git branch` first: if changes are sitting on `main`, move them onto a
branch immediately (`git checkout -b <branch>` carries unstaged changes across) before adding
anything of your own — do this without waiting to be asked. Then verify the inherited work
independently rather than trusting its plan file's checkboxes: re-run the build and full suite, and
prove any new regression test genuinely fails with the fix reverted.
