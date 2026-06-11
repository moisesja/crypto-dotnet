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
