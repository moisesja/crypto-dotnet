---
name: adversarial-pass
description: Run the independent adversarial exploitation pass that AGENTS.md requires before any security-relevant change is declared done. Use when you have finished implementing a change to crypto, key handling, signing, key stores, codecs, the FFI boundary, or any wrapper/delegation over them — and before saying "done". Also use when auditing existing boundary code.
---

# Adversarial pass

A change is not done until an independent agent has **tried to break it and reported**. Your
own round-trip tests prove the feature *works*; they do not prove it *cannot be abused*.

## When this is mandatory

Any security-relevant change. In this repository that is almost everything under `src/`:
crypto providers, key generation and the key model, signers and key stores, JWK conversion,
codecs, KDFs, AEADs, and the native FFI.

**Triviality is not a waiver.** "Thin wrapper", "just delegates", "no new crypto", "it only
exposes a constant" describes where the new *surface* is, not where the *risk* is. A wrapper
inherits the backend's exception and canonicalization behavior, and that seam is part of the
public contract — it is frequently wrong exactly there. If you catch yourself writing "it's
just a thin X so I'll skip the adversarial pass," that sentence is the trigger to run it.

Run it **before** declaring completion, not after the user asks.

## How to run it

Launch an independent subagent — not your own reasoning — with:

1. An explicit framing: **"Your job is to break this. Report every weakness you find."**
2. The instruction to **write and run exploit code** against the built artifact. Reasoning
   about the code is not a pass. If the environment blocks a scratch harness, say so
   explicitly in the report rather than silently downgrading to inspection.
3. A concrete attack list drawn from the checklists below.
4. A requirement to report findings **in detail**, including what it tried that did *not* work.

Take the report skeptically in both directions: a plausible-but-wrong forgery claim is worse
than none, so verify a finding before acting on it — and "zero findings" from a pass that only
fed bad inputs certifies input handling, not boundary integrity.

## Attack checklist — every change

- **Exception type at the seam.** Malformed and wrong-length input must produce a
  parameter-named `ArgumentException`, never a leaked backend or platform exception. See the
  `input-validation-sweep` skill and NFR-3.
- **Input canonicalization.** Does the codec or parser accept multiple textual forms for the
  same bytes (whitespace, padding variants, non-alphabet characters)? A canonical primitive
  must not.
- **Asymmetric arguments.** For any binding or commitment property, always include a test with
  **different-length** inputs, so a silent argument-order swap cannot pass via symmetry.
- **Boundary values.** Empty vs. 1-byte; zero scalars; curve-order boundaries (`n-1`, `n/2`,
  `n/2+1`); very large inputs (1 MB); embedded nulls.
- **Success ≠ validity.** Check whether an operation that returns successfully actually
  guarantees what the caller assumes. BBS `proof_gen` does not pre-validate the signature —
  the real gate is `VerifyProof`.

## Attack checklist — delegating and wrapping types

Required whenever the change wraps or delegates across a trust boundary (`IKeyStore`, an HSM
or KMS, an injected provider, the FFI). These three families are what an input-guard sweep
structurally cannot find — see NFR-6.

- **State mutation under a live handle.** Delete the delegated-to entity and recreate it with
  a *different* key under the same alias, then reuse the stale handle. Does the handle's
  advertised identity still match what it produces? Also: rebind, and use-after-delete.
- **Hostile or buggy backend output.** With a test-double backend, return for a *valid* input:
  a malformed result (wrong length, out-of-range recovery id); a well-formed but *wrong* result
  (correct shape, different key); a non-canonical result (high-S with adjusted parity). Verify
  the wrapper validates OUTPUT as strictly as it validates INPUT.
- **Advertised-vs-produced consistency.** For any type that both advertises an identity and
  produces identity-bearing output, assert `recover(output) == advertised identity` before the
  value is returned.
- **Mutable buffers, both directions.** Have the double retain and later write to the buffer it
  returned, and mutate the backing array of the `ReadOnlyMemory<byte>` it was handed. Neither
  may change what the caller observes, nor what the wrapper verified against.

## Definition of a completed pass

- Exploit code was written and executed (or the blocker is named in the report).
- Both checklists above were covered, with the second one covered whenever a boundary is involved.
- Every finding was fixed in `src/` or explicitly argued down with evidence — never pinned to a
  "known deviation" allow-list to keep the suite green.
- The result is recorded in the task's `tasks/todo{timestamp}.md` review section, including the
  attacks that found nothing.
