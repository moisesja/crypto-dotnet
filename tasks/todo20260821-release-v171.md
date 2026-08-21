# Release NetCrypto v1.7.1 — tag and push

Requested by owner after merging PR #31 to main.

## Pre-flight (verified, read-only)

- [x] `main` head is `b38a6c1` = merge of PR #31; contains the issue #30 validation fix, the
  flaky-test fix (`aa55d8f`), and the 1.7.1 version metadata.
- [x] `Directory.Build.props` on main: `NetCryptoVersion` = 1.7.1.
- [x] `CHANGELOG.md` on main: `[1.7.1]` heading closed with compare link. (Note: dated
  2026-08-20; today is 2026-08-21 — accepted as-is, not worth a main commit.)
- [x] `PublicAPI.Unshipped.txt`: 0 entries — per-release hygiene promotion has nothing to
  promote; no commit needed.
- [x] No `v1.7.1` tag exists; latest tag is `v1.7.0`.
- [x] `release.yml` triggers on `v*` tag push: builds the 5 native RIDs (`--locked`), packs
  `NetCrypto.1.7.1.nupkg`, verifies all 5 RID payloads, generates SHA256SUMS (6 entries),
  smoke-tests the packed package on 3 OS legs, then — gated on all prior jobs — creates the
  GitHub release `NetCrypto v1.7.1` with generated notes and pushes to NuGet via OIDC Trusted
  Publishing. The NuGet push is the irreversible step (a version can be unlisted, never
  replaced).
- [ ] `build.yml` on `b38a6c1` fully green (3/4 success; Windows in progress at plan time —
  will confirm green before tagging).

## Plan (on approval)

- [ ] Confirm all 4 `build.yml` checks green on `b38a6c1`.
- [ ] `git tag -a v1.7.1 b38a6c1 -m "NetCrypto 1.7.1"` — annotated, pointing at the merge
  commit.
- [ ] `git push origin v1.7.1` (retry per network policy if needed).
- [ ] Watch the `release` workflow: natives ×5 → pack+checksums → smoke ×3 → publish. Report
  each stage; on any failure before `publish`, nothing outward has happened — delete the tag,
  fix, re-tag.
- [ ] Verify outcomes: GitHub release `v1.7.1` exists with nupkg/snupkg/SHA256SUMS assets;
  NuGet shows NetCrypto 1.7.1.

## Review

(to be filled at completion)
