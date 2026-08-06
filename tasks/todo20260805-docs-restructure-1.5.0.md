# Doc restructure + NetCrypto 1.5.0 prep

## Goal

State each rule once, in the document that owns it: durable workflow policy in `AGENTS.md`,
normative product contract in `netcrypto-prd.md`, repeatable procedures as invocable skills,
and only the narrative *why* in `tasks/lessons.md`. Clean the `zcap-dotnet` content out of
`AGENTS.md §2a`. Prepare the library for 1.5.0, stopping before the tag.

## Scope and decisions

- Documentation, process, and release metadata only — no change under `src/`.
- The API baseline files are analyzer metadata, not public surface; promoting Unshipped →
  Shipped records what already shipped and changes no API.
- Release prep stops before the annotated `v1.5.0` tag (user decision): tagging fires
  `release.yml` → NuGet publish, which is irreversible and outward-facing.
- Lessons keep their narrative core and cite where the rule now lives, rather than being
  deleted — the *why* is what stops the mistake recurring.

## Plan

### Part 1 — Promote lessons into AGENTS.md

- [x] Merge L7 + L8 into one **plan gate** rule (they currently read as contradictory).
- [x] Add L10's **branch-before-first-edit** rule as Task Management step 0, plus the
      resume protocol.
- [x] Strengthen §4 with the two definition-of-done gates (adversarial pass, input-validation
      sweep), delegating the procedures to skills.

### Part 2 — Promote lessons into the PRD

- [x] NFR-3: three input families (absent / wrong-shape / structurally-valid-but-semantically-wrong);
      widen the forbidden-leak list with `OverflowException` and `KeyNotFoundException` (L3).
- [x] NFR-3 AC: the fuzz-lite suite runs on all three OS legs of FR-20 (L5).
- [x] New NFR-6 — Trust-boundary integrity, generalizing what FR-12b states for
      `KeyStoreSigner` alone (L9).
- [x] FR-5 AC: proof buffer sized from an upper bound; regression at the large end of the
      parameter space (L2).
- [x] Traceability appendix: NFR rows for the new requirement.

### Part 3 — Clean up the zcap-dotnet content

- [x] Replace the §2a workflow catalogue (caveat inheritance, attenuation, revocation,
      `tests/Compliance/`, Core/AspNetCore — none exist here) with NetCrypto-real dimensions.
- [x] Keep the opt-in policy and `pipeline()`-over-barriers guidance (both correct).

### Part 4 — Extract three skills

- [x] `.claude/skills/adversarial-pass/SKILL.md` — consolidates L4 + L6 + L9.
- [x] `.claude/skills/issue-kickoff/SKILL.md` — L10 + L7.
- [x] `.claude/skills/input-validation-sweep/SKILL.md` — the NFR-3 procedure.

### Part 5 — Trim lessons.md

- [x] Rewrite L1–L10 to narrative core + a citation of where the rule now lives.

### Part 6 — 1.5.0 release prep

- [x] `PublicAPI.Shipped.txt` — merge in the 36 entries stranded in `PublicAPI.Unshipped.txt`
      since GA 1.0.0 (all of 1.1.0–1.4.0's API, published but never promoted).
- [x] `Directory.Build.props` — `NetCryptoVersion` 1.4.0 → 1.5.0.
- [x] `CHANGELOG.md` — `[Unreleased]` → `[1.5.0] - 2026-08-05`; fresh `[Unreleased]`; add the
      missing compare link definitions for 1.1.0–1.5.0.
- [x] `README.md` — fix the stale GA note (pins `1.0.0`, claims Unshipped is empty).

## Acceptance evidence

- [x] Release build: 0 warnings, 0 errors.
- [x] Full suite (`Category!=BbsAbsent`) green at the #23 baseline count.
- [x] API coverage check passes; no public API or dependency change.
- [x] `git diff --check` clean.
- [x] No rule stated normatively in two documents.

## Review

### What moved where

| Lesson | Promoted to | Was it already there? |
|---|---|---|
| L1, L5 | NFR-3 (allow-list ban) | **Yes** — promoted earlier, lesson never trimmed |
| L6 | FR-16b AC (strict base64url) | **Yes** — same |
| L9 | FR-12b (boundary verification) | **Yes** — same, but scoped to `KeyStoreSigner` only |
| L3 | NFR-3 — three input families, widened forbidden-leak list | No |
| L5 | NFR-3 AC — all three OS legs | No |
| L9 | **NFR-6** — Trust-boundary integrity (generalized) | No |
| L2 | FR-5 AC — upper-bound proof sizing, large-end regression | No |
| L7 + L8 | AGENTS.md Task Management §2 — one plan-gate rule, both directions | No |
| L10 | AGENTS.md Task Management §0 — branch first, resume protocol | No |
| L4, L6, L9 | AGENTS.md §4 + `adversarial-pass` skill | Partially — §2 had one vague bullet |

The three "already there" rows are the reason for this task: a promoted rule left duplicated in
`lessons.md` is a rule with two copies free to drift. Each is now stated once and cited.

`lessons.md`: **19,530 → 9,977 bytes** (−49%). Zero `**Rule:**` / `**How to apply:**` blocks
remain (they were the duplicated normative text); all 10 lessons keep their narrative and carry a
`→ Rule:` citation to wherever the rule now lives.

### zcap-dotnet cleanup

`AGENTS.md §2a`'s "high-value workflows **in this repo**" listed chain validation, caveat
inheritance, attenuation, replay/nonce, revocation, `tests/Compliance/`, and Core / AspNetCore
projects — none of which exist in `crypto-dotnet`. Replaced with this library's real dimensions.
The opt-in policy and the `pipeline()`-over-barriers guidance were correct and repo-agnostic, so
they stayed. A grep for the zcap vocabulary across `AGENTS.md`, the PRD, `lessons.md` and the
skills now returns only one hit — "Porting caveats for agents" in PRD §1.4, ordinary English.

### Unplanned finding — the API baseline had been stale for four releases

Not in the original analysis; surfaced while checking release state. `PublicAPI.Shipped.txt` had
not been modified since `0b69535` (GA 1.0.0). All 35 API entries added across 1.1.0, 1.2.0, 1.3.0
and 1.4.0 were still in `PublicAPI.Unshipped.txt` despite having been published to NuGet, and
`README.md` asserted Unshipped was empty. Promoted all 35 (ordinal sort, matching the file's
existing order — verified before merging), and added a per-release hygiene note to PRD §8 so the
promotion is part of the release definition rather than something to rediscover.

Second unplanned finding: `.gitignore` covered `.claude/settings.json` but not
`settings.local.json` or `worktrees/`, so both were untracked-but-committable. Now ignored; the
three skills are checked in.

### Verification performed

| Check | Command | Result |
|---|---|---|
| Release build | `dotnet build -c Release -m:1` | succeeded, **0 warnings, 0 errors** |
| Full suite (CI filter) | `dotnet test --no-build -c Release --filter "Category!=BbsAbsent"` | **964 passed, 0 failed** — matches the #23 baseline |
| API surface | `dotnet run --project tools/ApiCoverageCheck -- samples` | passed; no public API or dependency change |
| Whitespace | `git diff --check` | clean |
| Duplication | grep for restated rules in `lessons.md` | 0 remaining, 10 citations present |

The Release build was the real gate for the baseline promotion: a mistyped or misordered entry
would have fired RS0016 ("symbol not part of the declared API") or RS0017 ("declared but not
present"). Zero warnings means the analyzer accepts all 203 entries against the actual surface.

### Commits

- `f877d57` — docs: promote lessons to AGENTS.md/PRD, add skills, fix zcap-dotnet content
- `7c85e2b` — chore: prepare 1.5.0 (API baseline, version, changelog)

### Deliberately not done

Creating and pushing the annotated `v1.5.0` tag. That fires `release.yml` → pack → 5-RID smoke →
GitHub release → **NuGet publish**, which is irreversible and outward-facing; the user chose
prep-only. The tree is ready for it: version bumped, CHANGELOG dated, baseline promoted, suite
green.
