---
name: issue-kickoff
description: Start an issue or feature task correctly — branch before the first edit, write the task plan, and apply the plan-approval gate. Use when picking up a GitHub issue or feature request, and when resuming someone else's unfinished work.
---

# Issue kickoff

The order matters. Branching is free and the first moment is the only cheap one; the cost of
skipping it is paid entirely by whoever picks the work up next.

## 1. Branch — before the first edit

```
git checkout -b <type>/<slug>-issue-<n>
```

Prefixes match the repo's history: `feat/`, `fix/`, `docs/`, `chore/`. This is the first tool
call after reading the issue — not at commit time, and never as a cleanup step.

Uncommitted work on `main` is the worst of both worlds: invisible to `git log`, lost to any
stray `checkout` or `stash`, unpushable, unreviewable, and it silently contaminates the next
task that starts from what looks like a clean tree.

## 2. Read the issue and the requirement

Find the FR or NFR in `netcrypto-prd.md` that governs the change. The PRD is the source of
truth for functionality; if the change adds or alters a contract, the PRD edit is part of the
task, not a follow-up.

## 3. Write the plan

`tasks/todo{timestamp}.md`, with checkable items, the scope decisions you made, and an
acceptance-evidence section. Mark items complete as you go and fill in a Review section at the
end.

## 4. Apply the plan gate — correctly in both directions

**Stop for approval before the first implementation edit** when the task builds or changes
something — unconditionally when it ends in publish / release / deploy, where the tail end
(merge, tag, NuGet push) is irreversible and outward-facing.

An energetic go-ahead in the task statement — "Go", "just do it", "deploy this as 1.4.0" —
authorizes the **outcome**, not the omission of the gate. Only the user approving the **plan
itself** skips it. The check-in is cheap; an irreversible release built on an unapproved plan
is not.

**Do not gate read-and-report tasks.** "Review this PR and post concerns or an approval",
"investigate X", "answer Y" are already instructions to perform the work and publish the
result. Write and maintain the plan file, then execute in the same run. Adding an approval
gate to work the user already authorized is as much an error as skipping one they didn't —
stop only if the target cannot be resolved safely or the requested external action is
genuinely ambiguous.

## 5. Resuming someone else's unfinished task

Run `git status` and `git branch` **first**.

- Changes sitting on `main`? Move them onto a branch immediately — `git checkout -b <branch>`
  carries unstaged changes across — before adding anything of your own. Do this without waiting
  to be asked.
- **Verify the inherited work independently.** Do not trust the plan file's checkboxes: re-run
  the build and the full suite yourself, and prove any new regression test genuinely fails with
  the fix reverted. Completed work and an abandoned half-edit look identical until you check.
- Re-run the `adversarial-pass` if the previous session's report shows it was blocked, skipped,
  or only inspected the code rather than executing against it.

## 6. Before declaring done

An implementation is not finished at the last passing test — it is finished when it is
committed on a named branch, with:

- the `adversarial-pass` skill run for any security-relevant change;
- the `input-validation-sweep` skill run for any new or migrated public surface;
- documentation, samples, PRD, and CHANGELOG current with the change;
- the Review section of the plan file filled in with commands and results.
