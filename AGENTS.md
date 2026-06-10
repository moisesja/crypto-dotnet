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
- Always use adversarial agents to attempt to exploit the code that is being generated. The adversarial agents must report in detail about any findings
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 2a. Workflow Orchestration (Multi-Agent)

- **Opt-in only**: launch a Workflow ONLY when the user explicitly asks (says
  "workflow", "fan out", "orchestrate with subagents") or runs a skill that
  calls it. Otherwise use a single subagent, or describe the workflow and its
  rough token cost and let the user decide. Never auto-launch — workflows can
  spawn dozens of agents and consume a large token budget.
- **High-value workflows in this repo**:
  - _Security review_ — fan out review dimensions (chain validation, caveat
    inheritance, attenuation, replay/nonce, revocation), then spawn N skeptics
    per finding to refute it; keep only findings that survive a majority vote.
  - _Spec-compliance sweep_ — one agent per normative requirement cluster →
    verify implementation + `tests/Compliance/` coverage → completeness critic
    flags untested MUST/SHOULD.
  - _Cross-package migration_ — discover call sites across Core / AspNetCore /
    examples / tests → transform each in worktree isolation → verify it builds.
  - _Test-gap analysis_ — multi-modal sweep by requirement, public API surface,
    and error path.
- **Default to `pipeline()` over barriers**: verify each finding as its review
  lands; only use a barrier when a stage genuinely needs all prior results
  (e.g. dedup before expensive verification).
- **Always adversarially verify security findings** — a plausible-but-wrong
  auth-bypass claim is worse than none.

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

# Task Management

1. **Plan First**: Write plan to `tasks/todo{timestamp}.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add a review section to 'tasks/todo{timestamp}.md'
6. **Capture Lessons**: Update 'tasks/lessons.md' after corrections
7. **Update Documents and Examples**: Always keep any relevant documentation and examples current with your code changes

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Staff Engineer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.
