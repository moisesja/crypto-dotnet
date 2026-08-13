# Lessons

What went wrong, and why — the narrative that stops the mistake recurring. The **rules** these
produced now live where they are enforced: workflow policy in [`AGENTS.md`](../AGENTS.md),
product contract in [`netcrypto-prd.md`](../netcrypto-prd.md), and procedures as skills under
[`.claude/skills/`](../.claude/skills/). Each lesson below cites its destination. When a new
correction produces a durable rule, promote it and leave the story here — don't restate the
rule in two places, because two copies drift.

## L1 — Verbatim migration silently carries latent backend-crash bugs

FR-1…FR-9 were migrated from net-did under a strict behavior-parity rule. The adversarial
review then found that secp256k1 `Sign`/`FromPrivateKey` crashed with `IndexOutOfRangeException`
on sub-32-byte keys (NBitcoin indexes a 32-byte span), and the BBS provider threw
`NullReferenceException` on null lists — both direct NFR-3 violations. Worse, the fuzz test
author had *pinned* the secp256k1 crash in a `KnownBackendDeviations` list to keep the suite
green. A test that documents a contract violation as "tolerated" hides the bug instead of
failing on it.

The trap is that "migrate verbatim" reads like it covers everything, so nobody re-derives the
invalid-input contract.

→ Rule: [`input-validation-sweep`](../.claude/skills/input-validation-sweep/SKILL.md)
("When a parity rule and NFR-3 collide"), NFR-3.

## L2 — Verify size/buffer formulas empirically, not from a code comment

`DefaultBbsCryptoProvider.DeriveProof` allocated its proof buffer from a comment formula
`144 + 32·(undisclosed+1)`; the true BLS12-381-SHA-256 proof size is `272 + 32·undisclosed`. A
512-byte floor masked the 96-byte shortfall for small reveals, so the existing tests (3
messages, reveal 2) passed — while ≥8 undisclosed messages threw `CryptographicException`. The
defect rode along through migration because no test exercised a large undisclosed count.

The floor is what made this survive: it turned a systematic error into one that only appears at
the far end of the parameter space, which is exactly where nobody had a test.

→ Rule: FR-5 acceptance criteria (upper-bound sizing; ≥10-message regression).

## L3 — Fuzz-lite must use malformed-but-present inputs, not just null/zero

The 2026-06-11 security review found the same crash-class as L1 in three more public methods
the original fuzz pass had missed: `JwkConverter.ExtractPublicKey` leaked a raw
`FormatException` on bad base64url, `KeyTypeExtensions.NormalizeToCompressed(null)` threw
`NullReferenceException`, and `ConcatKdf.DeriveKey` threw `OverflowException` on a huge
`keyDataLen`. `InputValidationFuzzTests` only fired null and all-zero buffers.

The subtlest part: zero buffers *look* like thorough negative testing but are a blind spot. For
P-256, `x = 0` decompresses to a valid point, so a zero-filled "bad key" silently took the happy
path — the test was green because the input wasn't actually bad.

→ Rule: NFR-3's three input families and forbidden-exception list;
[`input-validation-sweep`](../.claude/skills/input-validation-sweep/SKILL.md).

## L4 — The adversarial pass is not optional, and skipping it is most tempting when tests are green

For issue #2 (expose the BBS `header`) I implemented, ran happy-path plus a few negative tests,
and reported the task complete — without launching the adversarial agent AGENTS.md requires. The
user had to ask. The agent I then ran executed 24 exploit attempts and found no exploit — but it
*did* surface that BBS `proof_gen` does not pre-validate the signature, so success ≠ valid proof
and the real gate is `VerifyProof`. A semantic the happy-path tests actively obscured.

The lesson isn't "I got lucky." It's that green unit tests are the condition under which
skipping feels most justified and is least justified.

→ Rule: [`adversarial-pass`](../.claude/skills/adversarial-pass/SKILL.md), AGENTS.md §4.

## L5 — A permissive test contract hides real gaps

A preview.3 security review flagged that wrong-length raw keys leaked `System.FormatException`
(NSec), `Nethermind.Crypto.Bls+BlsException`, and a macOS `AppleCommonCryptoCryptographicException`
instead of a parameter-named `ArgumentException`. Two things let it survive: the fuzz assertion
tolerated `CryptographicException` as "in contract", so a platform crypto exception on a
wrong-length key passed; and the NSec/BLS leaks were pinned in `KnownBackendDeviations` — the
exact red flag L1 named, still there.

Also worth keeping: the macOS EC exception type differs from Windows and Linux, so "in contract
on my machine" hid a leak on other platforms.

The fix was an up-front `RawKeyGuard.RequireLength` at every backend hand-off, BLS exception
mapping, and deleting the allow-list entirely.

→ Rule: NFR-3 (parameter-named assertion, no allow-list, all three OS legs).

## L6 — "It's just a thin wrapper" is the rationalization, not an exemption

Implementing the 1.1.0 issues (#10 on-curve doc, #11 IKeyStore ECDH, #12 base64url + AEAD
constants), I shipped all three and declared them done without the adversarial pass. For #11 I
explicitly rationalized it — "the new path delegates to the already-tested `DeriveSharedSecret`,
it adds no new crypto." The user caught it.

The three agents I then ran found two real contract defects in exactly the code I'd dismissed as
too trivial to attack: `Base64Url.Decode` silently stripped ASCII whitespace (multiple wire forms
→ same bytes, contradicting both its own docs and the canonical-codec goal), and wrong-length
NIST EC peer keys leaked a platform `CryptographicException` — a gap my own #11 XML doc had
claimed was closed.

Neither was exploitable. Both were real. "Thin wrapper" describes where the new *surface* is,
not where the *risk* is: a wrapper inherits the backend's exception and canonicalization
behavior, and the seam is where that's usually wrong.

→ Rule: [`adversarial-pass`](../.claude/skills/adversarial-pass/SKILL.md) ("Triviality is not a
waiver"); FR-16b AC (strict base64url).

## L7 — "Go" authorizes the goal, not skipping the plan-approval checkpoint

For issue #21 ("deploy this single issue as version 1.4.0 … Go") I wrote the plan file and
immediately started implementing on a branch without checking in. The user interrupted: "How
come you aren't giving me a plan to approve?" A release task is exactly where the checkpoint
matters most, because the tail end — merge, tag, NuGet publish — is irreversible.

→ Rule: AGENTS.md Task Management §2; [`issue-kickoff`](../.claude/skills/issue-kickoff/SKILL.md).
Paired with [[L8]] — the gate has two failure modes, and this is only one of them.

## L8 — A direct review command authorizes execution; do not turn it into a plan gate

The user asked me to inspect a newly opened PR and post either specific concerns or an approval.
I created the task plan, then stopped and asked them to approve *the plan*. The correction: the
request was already an instruction to perform the review and publish the result, not an
invitation to negotiate the workflow.

The pair [[L7]]/[[L8]] is the actual lesson. Over-gating costs as much credibility as
under-gating, and reading them separately produces exactly the wrong instinct — apply the gate
everywhere, or nowhere.

→ Rule: AGENTS.md Task Management §2 (both directions stated together);
[`issue-kickoff`](../.claude/skills/issue-kickoff/SKILL.md).

## L9 — "Zero findings" from an input-only pass certifies input handling, not boundary integrity

For issue #21 an adversarial pass reported "57 exploit tests, zero findings" and I declared the
code sound. Two human reviews and a second, deeper pass then found three real defects on the
`KeyStoreSigner`/`IKeyStore` seam: **alias rebinding** — delete an alias, recreate it with a new
key, and an old signer still signs with the new key while advertising the old public key; a
**malformed store output** (`RecoverableSignature([0x01], 27)`) passing straight through a
contractually-64-byte API; and the DIM default throwing `NotSupportedException` instead of the
documented `ArgumentException("digest32")`.

What made the first pass feel thorough: it tested input guards exhaustively — lengths, null,
wrong key type, disposed, even a bogus store. But it only ever checked that the *length guard
fires first*, never what happens to a garbage result for a *valid* digest; and it tested import
under two aliases but never delete-then-recreate. Fifty-seven tests, all on one side of the
boundary.

The second pass added the buffer dimension: a wrapper caching identity bytes must clone
constructor input, and one that verifies a request after the provider returns needs two copies,
because a provider can recover and mutate the backing array of a `ReadOnlyMemory<byte>`.

→ Rule: NFR-6 (Trust-boundary integrity), FR-12b;
[`adversarial-pass`](../.claude/skills/adversarial-pass/SKILL.md) ("delegating and wrapping
types"). See [[L4]], [[L6]].

## L10 — Issue work belongs on a branch from the first edit

Issue #23 was picked up by an earlier agent that implemented the fix, the tests, and all four
documentation surfaces — then stopped without ever committing. The entire change sat as unstaged
modifications on `main`: seven modified tracked files plus an untracked plan file. The work
itself was sound; the only thing wrong was where it lived.

Uncommitted work on `main` is the worst of both worlds — invisible to `git log`, lost to any
stray `checkout` or `stash`, unpushable, unreviewable, and it silently contaminates the next
task that starts from what looks like a clean tree. And leaving verified work uncommitted throws
away the verification itself: the next agent cannot tell completed work from an abandoned
half-edit without re-deriving all of it.

→ Rule: AGENTS.md Task Management §0;
[`issue-kickoff`](../.claude/skills/issue-kickoff/SKILL.md) (branch first; resume protocol).

## L11 — Validation in a record's property *initializer* is not validation

Building the issue #26 custody surface, I put every guard in a property initializer —
`public string Value { get; init; } = Validate(Value, …);` — and wrote a design note claiming
the `with`-expression hole "is not closable by the type itself". Both gates disagreed. A
property initializer runs in the primary constructor only; the record copy-constructor copies
backing fields and `with` calls the auto-implemented `init` setter, so every check is skipped.
The NFR-3 sweep confirmed it on 20 members across six types.

That would have been a footnote if the identifier structs were the only victims — the store
re-validates those at every entry point, by design. But `KeyStoreCapability` and
`KeyStoreCapabilitySet` were re-validated nowhere, so a `with` could produce a `Sign` capability
with no algorithm, a zero byte-bound, or a capability list containing `null` — and `Find`,
`Equals`, and `GetHashCode` then threw `NullReferenceException`, which is on NFR-3's forbidden
list. It also falsified the XML doc I had written promising the caller's list could not change
what a store advertised.

The fix was already in the codebase: `StoredKeyInfo.PublicKey` validates on its `init`
accessor, which is `with`-safe. I had the pattern in front of me and used the weaker one.

→ Rule: validate on the `init` accessor, never in a property initializer, for any record whose
invariants matter. `default(T)` on a `record struct` remains genuinely unclosable and is what
consumer-side re-validation is for — don't let the two blur together. FR-7b AC;
[`input-validation-sweep`](../.claude/skills/input-validation-sweep/SKILL.md) family (c).

## L12 — A length check on backend output is not an identity check

The same surface validated provider results by length and called that NFR-6 compliance — the
XML doc on the helper literally said it "validates a provider result before it reaches the
caller (NFR-6)". The adversarial pass returned a well-formed 64-byte P-256 signature made under
a *different key* and the store handed it to the caller; 80 bytes of `0xAB` passed as a BBS
signature; a single `0xDE` byte passed as DER, where no length check applies at all.

NFR-6.2 asks for `recover(output) == advertised identity`, and the repo already does exactly
that in `KeyStoreSigner.CopyAndVerify` — on the *recoverable* path, where it was easy because a
recoverable signature encodes its own signer. I generalized the alias-rebinding half of that
defense to the new surface and left the identity half behind, because on the ordinary signing
path it costs a verification. [[L9]] is the same shape one level up: that pass certified input
handling and missed the boundary; this one certified output *shape* and missed output *meaning*.

One further turn of the screw the pass forced: verify through an internal provider, not the
injected one. A provider that forged the signature will happily verify it too.

→ Rule: NFR-6, FR-7b rule 11; [`adversarial-pass`](../.claude/skills/adversarial-pass/SKILL.md)
("hostile or buggy backend output"). See [[L9]].
