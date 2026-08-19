---
name: input-validation-sweep
description: Sweep the public surface against the three input families NFR-3 requires, before declaring a migration or phase done. Use when auditing any parse, import, convert, or key-loading method, after any verbatim migration, or when a review flags a leaked backend exception.
---

# Input-validation sweep (NFR-3)

Every public method validates lengths and nulls and throws `ArgumentException` /
`ArgumentNullException` **with the parameter name** before any crypto operation. This skill is
the procedure for proving that; NFR-3 in `netcrypto-prd.md` is the normative contract.

## The three input families

Driving only nulls and zeros certifies almost nothing. Cover all three:

| Family | What it means | Examples |
|---|---|---|
| **(a) Absent** | Nothing there | `null`, empty span |
| **(b) Wrong-shape** | Present, obviously wrong size | wrong length, oversized, non-multiple-of-block |
| **(c) Structurally-valid-but-semantically-wrong** | Passes the cheap checks, breaks the next layer | valid base64 that is not valid base64url; an off-curve point that still parses; a coordinate on-curve by value but left-zero-trimmed in length; a high-S signature; an index past the message count; an oversized length *parameter* |

**Family (c) is where the defects hide** — (a) and (b) fail fast in obvious ways. Every public
method that parses caller bytes needs at least one family-(c) negative test.

When auditing a method, the question to ask is: *"what input passes the cheap length/null
checks but breaks the next layer?"* — then write that test.

> **Zero buffers are a blind spot, not a family-(c) test.** For P-256, `x = 0` decompresses to
> a *valid* point, so a zero-filled "bad key" silently takes the happy path. Feed non-zero
> random and valid-encoding-of-invalid-value buffers.

## Forbidden leaked exception types

Originating in NetCrypto or one of its dependencies, from any public method and on any input:

`IndexOutOfRangeException` · `NullReferenceException` · `System.FormatException` ·
`OverflowException` · `KeyNotFoundException` (where not the documented contract) · any backend
or platform type (`Nethermind.Crypto.Bls+BlsException`, NSec's `FormatException`, a platform
`CryptographicException` from EC import)

All must become `ArgumentException` / `ArgumentNullException` with the parameter name — or a
documented `false` return for verify-style methods. `CryptographicException` is reserved for
genuine crypto failures and must **not** double as the catch-all for malformed input.

### Caller-callback exception boundary

A higher-order method does not translate an exception that escapes execution of a
caller-supplied delegate unless its contract explicitly says otherwise. This includes an
exception raised by code or dependencies the delegate invokes: the API cannot infer provenance
inside caller code. The same exception instance propagates. This is an execution-boundary rule,
never a type allow-list: the same `FormatException` is permitted when it escapes the delegate
and forbidden when NetCrypto or a dependency raises it outside that call. Always assert the
method's security postconditions (for example, consumption and zeroization) even when the
callback throws.

## Procedure

1. **Enumerate the surface.** Every public method that accepts caller bytes, a length, an
   index, or a string to parse.
2. **Guard before the hand-off.** For anything forwarding bytes to a third-party, native, or
   platform backend, validate length and other cheap invariants *before* the call, and map any
   residual backend exception to `ArgumentException(paramName)`.
3. **Assert the parameter, not a set.** Write `.WithParameterName("digest32")`, never "threw
   something in {A, B, C}". A broad pass condition certifies far less than it appears.
4. **No allow-list.** The suite carries no `KnownBackendDeviations` or equivalent. A test that
   documents a contract violation as "tolerated" hides the bug instead of failing on it — fix
   `src/` instead.
5. **Probe every OS.** Backend failure types are platform-specific: the macOS EC import
   exception differs from Windows and Linux. "In contract on my machine" can hide a leak
   elsewhere, so the suite must be green on all three CI legs (FR-20).

## When a parity rule and NFR-3 collide

"Migrate verbatim" applies to **valid-input** behavior, wire formats, names, and exception
types. It does not exempt the public surface from NFR-3. On *invalid* input the NFR wins: add
the guard. Converting a crash into the contractually-required `ArgumentException` changes no
valid-input behavior, so parity and the migrated tests both still hold.

Run this sweep after any verbatim migration, **before** declaring the phase done.

## Related

- Output-side validation at a trust boundary is NFR-6 — see the `adversarial-pass` skill.
- Variable-length outputs: size buffers from an upper bound and add a large-end regression
  test, per FR-5.
