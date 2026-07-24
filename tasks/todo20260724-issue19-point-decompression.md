# Issue #19 — Public secp256k1 compressed→uncompressed point decompression → release 1.3.0

Issue: https://github.com/moisesja/crypto-dotnet/issues/19
Goal: public, validated, compressed → uncompressed EC point API; ship as **1.3.0** (blocks
net-did `feat/did-ethr-resolver`, which needs `0x04‖X‖Y` from a bare 33-byte compressed key).

## Design

`KeyTypeExtensions.ToUncompressed(this KeyType, byte[] publicKey)` — symmetric with
`NormalizeToCompressed`, per the issue's proposal:

- Input: compressed SEC1 (`0x02/0x03` prefix) → decompressed to 65/97/133-byte `0x04‖X‖Y`.
- Already-uncompressed input (`0x04`, right length) → **validated** pass-through (returned as a
  copy), mirroring `NormalizeToCompressed`'s tolerant input handling.
- Supported: Secp256k1 (the concrete need) + P-256/P-384/P-521 (trivial via the existing internal
  `DefaultCryptoProvider.DecompressEcPoint`). Non-EC key types throw.
- Errors: `ArgumentNullException` for null; parameter-named `ArgumentException` for everything
  else (bad length, bad prefix, off-curve) — NFR-3; no `CryptographicException` leaks from the
  decompress path, no public NBitcoin types (NFR-1).

## Todo

- [ ] Branch `feat/point-decompression-issue-19`
- [ ] Implement `KeyTypeExtensions.ToUncompressed` (reuse `DecompressEcPoint` / NBitcoin `ECPubKey` already used in this file)
- [ ] Fix now-stale `EcPointValidator` XML remark ("decompression is internal-only")
- [ ] Tests (`tests/NetCrypto.Tests/Crypto/`): round-trips for all 4 EC types, secp256k1 SEC1 G vector, NIST cross-check vs BCL `ECDsa`, equality with `Secp256k1Recoverable.RecoverPublicKey(compressed:false)` (the issue's Ethereum use case), pass-through copy semantics, and NFR-3 negatives incl. family-(c) off-curve-but-parseable inputs (lesson L3)
- [ ] Update `samples/NetCrypto.Samples.Keys` §5 (FR-17 mechanical coverage check requires the method name in samples)
- [ ] PRD: add **FR-19 — Public EC point decompression (1.3.0, issue #19)** with acceptance criteria
- [ ] CHANGELOG 1.3.0 entry; bump `Directory.Build.props` `NetCryptoVersion` → 1.3.0
- [ ] `dotnet build -warnaserror` + full test suite + run Keys sample
- [ ] Adversarial exploit pass (writes AND runs exploit code — lessons L4/L6, non-negotiable)
- [ ] PR "Closes #19" → merge → tag `v1.3.0` → push tag
- [ ] Watch `release.yml` (natives → pack → smoke → publish); confirm NuGet 1.3.0 + GitHub release
- [ ] Review section below

## Review

**Shipped:** `KeyTypeExtensions.ToUncompressed(this KeyType, byte[])` — public, validated
compressed→uncompressed EC point decompression for secp256k1 + P-256/P-384/P-521, the inverse of
`NormalizeToCompressed`. Reuses the existing internal `DefaultCryptoProvider.DecompressEcPoint`
(NIST) and the NBitcoin `ECPubKey` path (secp256k1) already present in the file; no new NBitcoin
surface (NFR-1). Uncompressed input is a validated defensive-copy pass-through; off-curve points
never pass unchecked (invalid-curve defense). All invalid input → `ArgumentNullException` /
parameter-named `ArgumentException` (NFR-3); internal `CryptographicException` from the decompress/
validate layer is caught and re-thrown as `ArgumentException(publicKey)`.

**Beyond the issue's minimum:** the issue only required secp256k1. Extended to all four EC curves
since `DecompressEcPoint` already covers the NIST ones trivially. Also rejects SEC1 *hybrid*
encodings (0x06/0x07) — one point, one accepted wire form.

**Verification:**
- `dotnet build -warnaserror` clean (0 warnings).
- 46 new tests pass; full suite 913/913 (the 5 `BbsUnavailable` failures are pre-existing and
  environmental — they assert the BBS native lib is *absent*; it's present locally; fail 5/5 on
  pristine main too).
- Keys sample runs to exit 0 with the new Ethereum-address demo; API coverage check passes.
- **Two adversarial exploit passes** (L4/L6), ~426k hostile calls combined with independent
  BigInteger/BCL/NBitcoin oracles and a proven negative control: **zero findings** — no exception
  leaks, no off-curve output, no cross-curve confusion, correct Y parity, no input mutation,
  defensive output copy.

**Non-blocking note for a future refactor:** the NIST compressed path's `x < p` range check is
enforced at the final `EcPointValidator.EnsureMatchesRhs` gate inside the shared
`DecompressEcPoint`, not as an early check. Empirically correct (mod-p wraparound spoofs all
rejected) and shared with `ImportEcPublicKey`, so left untouched to avoid scope creep; a refactor
that returns before `EnsureMatchesRhs` would need to re-add the guard.
