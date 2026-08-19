# Prepare 1.7.0 release + push to PR #29

Branch: `fix/transferable-consume-public-issue-28` (PR #29). Requested: "prepare everything to
deploy version 1.7.0 and push to the PR."

## How deploy actually works here (from `.github/workflows/release.yml`)
- Release is **tag-triggered**: pushing a `v*` tag runs natives → pack → smoke → publish, and
  `publish` **pushes to NuGet** (Trusted Publishing) and creates the GitHub release. That push is
  **irreversible** — a NuGet version cannot be reused or truly unpublished.
- `build.yml` runs on the PR itself (build + full test + samples + coverage across 3 OS legs +
  the no-native leg). Merging is gated on that, not on the tag.
- The tag publishes from **whatever commit it points at**. Every prior tag (v1.0.0…v1.6.0)
  corresponds to a release; the established flow is to tag on `main`, i.e. **after the PR merges**.

## State already correct (verified)
- `Directory.Build.props` `NetCryptoVersion` = **1.7.0**.
- `CHANGELOG.md` has a dated `## [1.7.0] - 2026-08-18` section (Changed + Fixed).
- `PublicAPI.Shipped.txt` carries the #28 members; `PublicAPI.Unshipped.txt` is empty. Build is
  `-warnaserror` clean (RS0016/RS0017).
- Local `dotnet pack` produces **`NetCrypto.1.7.0.nupkg`** with `<version>1.7.0</version>` and the
  README embedded — version stamping confirmed.
- No stray version strings: the remaining `1.6.0` references are the `NetCid` dependency and the
  historical "ICapableKeyStore (1.6.0)" prose, both correct.

## Gap found
- **G1 — CHANGELOG comparison-links footer is stale.** It still reads
  `[Unreleased]: …compare/v1.6.0...HEAD` with no `[1.7.0]` link. The 514b8a8 release-prep commit
  omitted it. Needs:
  - `[Unreleased]: …/compare/v1.7.0...HEAD`
  - `[1.7.0]: …/compare/v1.6.0...v1.7.0` (inserted above the `[1.6.0]` line)

## Plan (release prep — additive, no code change)
- [x] R1 Fix the CHANGELOG footer links (G1).
- [x] R2 Re-verify: `dotnet build -warnaserror` clean, `dotnet pack` → `NetCrypto.1.7.0.nupkg`,
      full suite green under the CI filter (already green at HEAD; re-confirm nothing regressed).
- [ ] R3 Commit `chore: finalize 1.7.0 changelog links` on the branch and **push to PR #29**.
- [ ] R4 Post a short PR comment noting the release is prepared and how the deploy tag should be cut.

## The one decision that is yours (irreversible) — see question
**Whether/when to push the `v1.7.0` tag.** Two options:
- **A (recommended): prep only; do NOT tag from the branch.** Push release prep to PR #29; the
  `v1.7.0` tag is cut on `main` after the PR merges and CI is green, which is how every prior
  release was done. Nothing irreversible happens now.
- **B: also push `v1.7.0` now**, pointing at the PR branch head. This triggers the live NuGet
  publish immediately, from an **unmerged** commit, bypassing the merge and the PR's own CI gate.

## Out of scope
- No source/behavior change; 1.7.0 content is already implemented and tested.
- Not merging the PR (maintainer action).

## Review

Chosen: **prep + push to PR only** (no tag) — deploy trigger stays a post-merge tag on `main`.

- **R1** CHANGELOG footer links updated: `[Unreleased]` now `v1.7.0...HEAD`, added
  `[1.7.0]: …/compare/v1.6.0...v1.7.0`.
- **R2** `dotnet build NetCrypto.sln -c Release -warnaserror` → 0 warnings/0 errors;
  `dotnet pack` → **NetCrypto.1.7.0.nupkg** (`<version>1.7.0</version>`, README embedded);
  full suite green under the CI filter (NetCrypto.Tests 1229, ExternalStore.Tests 15, 0 failed).
- **R3** Committed on the branch and pushed to PR #29.
- **R4** PR comment posted describing release-readiness and the tag-on-main-after-merge step.

**Not done (deliberately, per the approved decision):** no `v1.7.0` tag pushed. The release
workflow is tag-triggered and publishes to NuGet irreversibly; the tag is cut on `main` after
the PR merges and `build.yml` is green, matching every prior release. Merging PR #29 is a
maintainer action.

