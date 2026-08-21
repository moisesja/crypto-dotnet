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

## Review — BLOCKED at the tag push (needs a human with push rights)

Approved and executed up to the irreversible step, where the session's own credential refused
the operation.

### Done

- All four `build.yml` checks confirmed green on `b38a6c1` (ubuntu, windows, macos, no-native).
- Annotated tag created locally: `v1.7.1` → `b38a6c1`, message "NetCrypto 1.7.1".

### Blocked

- `git push origin v1.7.1` → `HTTP 403` from GitHub, twice (one retry per the network policy).
- Diagnosis — this is a credential-scope denial, not a network fault or a repo rule:
  - `curl $HTTPS_PROXY/__agentproxy/status` reports `recentRelayFailures: []`, so the egress
    proxy did not block it; the 403 came from GitHub.
  - `GET /repos/moisesja/crypto-dotnet/rulesets` returns `[]` — no tag protection rule.
  - Branch pushes from this same session succeed (`claude/wonderful-meitner-npokuk` pushed
    minutes earlier), so the credential is scoped to `refs/heads/*` and refuses `refs/tags/*`.
  - The GitHub MCP toolset matches that boundary: `create_branch` exists, but every tag and
    release tool available is read-only (`get_tag`, `list_tags`, `get_release_by_tag`,
    `list_releases`, `get_latest_release`). There is no create-tag or create-release tool.
- Not routed around. `release.yml` has no `workflow_dispatch` trigger, and its version comes
  from `${GITHUB_REF_NAME#v}`, so firing it by any means other than a real `v*` tag push would
  be both impossible and wrong. Per `/root/.ccr/README.md`, a 403 policy denial is reported,
  not worked around.

### State left behind

- Remote is **unchanged**: `git ls-remote --tags origin` shows no `v1.7.1`; latest remote tag is
  still `v1.7.0`. The `release` workflow never ran. Nothing was published to NuGet, and no
  GitHub release was created. `main` at `b38a6c1` is green and carries correct 1.7.1 metadata.
- A local-only `v1.7.1` tag exists in this ephemeral container; it has no effect on the remote
  and disappears with the session.

### Handoff — run from a checkout with push rights

```
git fetch origin main
git tag -a v1.7.1 b38a6c1 -m "NetCrypto 1.7.1"
git push origin v1.7.1
```

That push triggers `release.yml`: natives ×5 → pack + checksums → smoke ×3 → publish (GitHub
release + NuGet). Everything before `publish` is reversible — on failure, `git push --delete
origin v1.7.1`, fix, re-tag.
