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

See the Review section at the end of this file (filled in on completion).
