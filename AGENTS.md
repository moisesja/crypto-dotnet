# Agent & Contributor Instructions

This file provides instructions for AI agents and human contributors working in this codebase.

## Project Overview

NetCrypto is the single home for every cryptographic primitive in the library stack, behind stable interfaces, so that no domain library ever binds directly to a specific crypto implementation (NSec, NBitcoin.Secp256k1, Nethermind.Crypto.Bls, the zkryptium FFI, or the .NET base class library).

Today these primitives live inside `net-did`, which forces an inversion: future libraries that need signing or key handling — `dataproofs-dotnet`, `credentials-dotnet`, `didcomm-dotnet` — would have to depend on the _DID_ library to get _crypto_. Extracting the primitives into a foundation package restores the intended layering:

```
                net-wallet-sdk
   ┌──────────┬──────┴───────┬─────────────┐
credentials-dotnet  zcap-dotnet  didcomm-dotnet
   └──────────┴──────┬───────┴─────────────┘
              dataproofs-dotnet        net-did
                     └────────┬───────────┘
                          NetCrypto
                              │
                           net-cid
```

(Layering shown top-down by dependency; arrows omitted — every box depends on the boxes below it on its path.)

## Requirements and Design

For the overall vision use [`netcrypto-concept.md`](netcrypto-concept.md) as the goal to achieve. See [`netcrypto-prd.md`](netcrypto-prd.md) for requirements and instructions on how to build the system. This document must be maintained as it will be the main source of truth for functionality details.

## Workflow Orchestration

### 1. Plan Mode Fault

- Enter plan mode for ANY non-trivial task defined as a task that takes 3 steps or more or that requires architectural decisions.
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy

- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- Always use adversarial agents to attempt to exploit the code that is being generated. The adversarial agents must report in detail about any findings — run the `adversarial-pass` skill, which carries the procedure and the attack checklist
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 2a. Workflow Orchestration (Multi-Agent)

- **Opt-in only**: launch a Workflow ONLY when the user explicitly asks (says
  "workflow", "fan out", "orchestrate with subagents") or runs a skill that
  calls it. Otherwise use a single subagent, or describe the workflow and its
  rough token cost and let the user decide. Never auto-launch — workflows can
  spawn dozens of agents and consume a large token budget.
- **High-value workflows in this repo**:
  - _Security review_ — fan out over this library's actual risk dimensions:
    input validation (NFR-3), trust-boundary integrity (NFR-6), key-material
    lifetime and zeroization (FR-18), signature malleability and encoding
    canonicalization, and native FFI marshalling. Then spawn N skeptics per
    finding to refute it; keep only findings that survive a majority vote.
  - _Spec-vector coverage sweep_ — one agent per vector source (RFC 8032, 5869,
    3394, 7518 §5.2.2, draft-irtf-cfrg-bbs-10, draft-irtf-cfrg-xchacha-03, NIST
    CAVP GCM) → confirm each vector is pinned against **published bytes**, not
    writer/reader parity → completeness critic flags any FR whose AC cites a
    spec with no corresponding test.
  - _Public API surface diff_ — reflect over the built assembly, diff against
    `PublicAPI.Shipped.txt` + `PublicAPI.Unshipped.txt`, and check NFR-1
    (no NSec/NBitcoin/Nethermind/Native type in a public signature).
  - _Cross-RID packaging verification_ — FR-21/FR-22: unpack the `.nupkg`, prove
    all five `runtimes/{rid}/native/` payloads are present under the exact
    filenames .NET probes for, and smoke one BBS round-trip per available RID.
- **Default to `pipeline()` over barriers**: verify each finding as its review
  lands; only use a barrier when a stage genuinely needs all prior results
  (e.g. dedup before expensive verification).
- **Always adversarially verify security findings** — a plausible-but-wrong
  key-recovery or forgery claim is worse than none.

### 3. Self-Improvement Loop

- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done

- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness
- **Adversarial gate.** For any security-relevant change, an independent
  adversarial pass is part of the definition of done, not a follow-up. Run it
  BEFORE declaring completion, never after being asked. "Thin wrapper", "just
  delegates", "no new crypto" is not a waiver — a wrapper inherits the backend's
  exception and canonicalization behavior, and that seam is part of the public
  contract. Procedure: the `adversarial-pass` skill.
- **Input-validation gate.** Before declaring any migration or phase done, sweep
  the public surface against the three input families NFR-3 names. Procedure:
  the `input-validation-sweep` skill. Never pin a contract violation to a
  "known deviation" allow-list to keep the suite green — fix `src/`.
- **Prove the regression test is genuine.** Revert the fix, confirm the new test
  fails at the intended assertion, restore. A test that passes either way
  documents nothing.

### 5. Demand Elegance (Balanced)

- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing

- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

## Skills

Repeatable procedures live as skills under `.claude/skills/`, so this file states the policy
once and the steps load only when you are actually running them. Invoke by name.

| Skill | Run it when |
|---|---|
| `issue-kickoff` | Starting any issue or feature — branch, read, plan, gate |
| `adversarial-pass` | Before declaring any security-relevant change done |
| `input-validation-sweep` | Before declaring a migration or phase done; when auditing a parse/import/convert method |

# Task Management

0. **Branch First**: Create the branch **before the first edit**, not at commit time and
   never as a cleanup step: `git checkout -b <type>/<slug>-issue-<n>` (`feat/`, `fix/`,
   `docs/`, `chore/`) as the first tool call after reading the issue. An implementation is
   not finished at the last passing test — it is finished when it is committed on a named
   branch. When **resuming** someone else's unfinished task, run `git status` and
   `git branch` first: changes sitting on `main` move onto a branch immediately
   (`git checkout -b <branch>` carries unstaged changes across) before you add anything of
   your own, without waiting to be asked. Then verify the inherited work independently
   rather than trusting its plan file's checkboxes.
1. **Plan First**: Write plan to `tasks/todo{timestamp}.md` with checkable items
2. **Verify Plan**: Write the plan file and stop for approval before the first
   implementation edit — unconditionally for any task ending in publish / release / deploy,
   where the tail end is irreversible and outward-facing. An energetic go-ahead in the task
   statement ("Go", "just do it") authorizes the *outcome*, not the omission of the gate;
   only the user approving the **plan itself** skips it. The gate does **not** apply to
   read-and-report tasks — review a PR, investigate, answer a question: write the plan file,
   then execute and publish the result in the same run. Adding an approval gate to work the
   user already authorized is as much an error as skipping one they didn't.
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add a review section to 'tasks/todo{timestamp}.md'
6. **Capture Lessons**: Update 'tasks/lessons.md' after corrections — the narrative of what
   went wrong and why. If the correction is a durable rule, promote it: workflow policy to
   this file, product contract to `netcrypto-prd.md`, a repeatable procedure to a skill under
   `.claude/skills/`. State a rule in exactly one place and cite it from the others.
7. **Update Documents and Examples**: Always keep any relevant documentation and examples current with your code changes

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Staff Engineer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.
