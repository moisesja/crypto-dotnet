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
