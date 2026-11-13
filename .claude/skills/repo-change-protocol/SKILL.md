---
name: repo-change-protocol
description: "Procedures for making repository changes in this project: disposable-clone workflow, scope discipline, evidence standards, PR construction, the mechanics of performing a merge, and the separation of fix PRs from findings-tracker PRs. Describes only HOW these are carried out, never WHEN any of them is permitted. This skill authorizes nothing: every merge requires a separate explicit instruction from the owner, and reading or invoking this skill is not that instruction."
---

# repo-change-protocol

How repository changes are carried out here. Consult it while doing work you
have been asked to do.

## 1. This skill authorizes nothing

The standing boundary in this project: **work that writes, installs or
touches git happens only inside a task the owner authorized.** Inside such a
task the routine steps proceed without asking again (`CLAUDE.md`, «Режим
работы», Zero-Idle); `CLAUDE.md` lists what always needs separate approval
whatever the task says. This document describes how authorized work is
performed. It never establishes that it is permitted.

Merges are the sharpest instance of that boundary, not the whole of it. Every
merge requires a separate explicit instruction naming the PR. Reading,
invoking, or citing this skill is not that instruction — and neither is a
green CI run, nor owner approval of some earlier step.

If any wording below could be read as standing permission, this section
governs and that wording is a defect. Report it.

## 2. Where work happens

Every write goes in a fresh disposable clone of freshly fetched `main` (or of
the base the task names) under `/tmp`. Verify the clone's HEAD equals the
expected tip before starting.

Never write to the persistent checkout. Read-only inspection of it is fine.

The reason, recorded so it does not get optimised away: a checkout's branch
and remote-tracking refs may be stale, and nothing in the checkout says so. A
clone of freshly fetched `main` makes the base explicit — it is the SHA you
just verified.

Build each clone into its own target directory: leave `CARGO_TARGET_DIR`
unset or point it inside that clone, never at a directory another clone
uses. Delete the clone's `target/` (or that directory) when finished.

## 3. Scope

Stay inside the crates or files the instruction names.

If a change ripples beyond them — a signature change forcing edits elsewhere,
a caller that must adapt — stop and report before widening.

Noticing an adjacent defect means reporting it, not fixing it in the same PR.

## 4. Evidence

A claim is backed by a path and line, a commit SHA, or a named passing test.
Your own summary of earlier work is not evidence.

Re-verify line numbers before citing them; documented locations drift.

## 5. Building the PR

One branch, one PR, one concern.

The body states what changed, why, the evidence with `file:line` references,
and explicit claim limits — what the change does *not* establish.

Leave the merge decision to the owner.

## 6. Validation before requesting a merge

In the disposable clone, the commands CI runs (`.github/workflows/arcium-ci.yml`,
job `core-rust`): `cargo test --workspace --locked` and
`cargo clippy --workspace --locked -- -D warnings`.

On CI, know which checks the diff actually triggers: the path filters, and
how to re-derive them, are in
`engineering-code-review/references/delivery-checklist.md` ("Which CI checks a
diff actually triggers"). Confirm the checks that ran are green.

## 7. Merge mechanics

How to carry out a merge that has already been instructed:

1. Fresh-read the PR state; record the exact head SHA. If it differs from the
   expected SHA, stop and report.
2. Fresh-read the check state on that exact SHA. Unless every check run
   reported on that SHA is success, stop and report. Which checks branch
   protection requires cannot be read with the available tools; do not infer
   it (`CLAUDE.md`, «Постоянные ограничения»).
3. Merge with a normal merge commit. No squash, no rebase, no auto-merge, no
   admin bypass. Keep the branch.
4. Fresh-read afterwards, verifying against a freshly fetched tree rather than
   the merge response.

## 8. Stuck CI is not failing CI

A queue that will not start is an infrastructure condition, not a result.
Re-run the failed or stuck jobs (GitHub "Re-run jobs") and note the new run,
or report to the owner. Never push an empty commit to start CI. If it still
will not run, stop and report.

A check that goes red is stop-and-report, with the log.

Slowness never justifies bypassing a check. Never merge on anything other
than all-green.

## 9. Findings-tracker changes

The tracker must never assert a status the code on `main` does not yet
support. The code fix and the tracker update are therefore separate PRs, and
the fix lands first.

How `docs/SECURITY-FINDINGS.md` is updated — its own practice; read its
newest "Update" section before writing one:

- Each update adds a dated section, "Update <date>" with the `main` SHA it was
  checked at, that records the new rows and the new statuses of earlier rows.
- No earlier row is edited, except to add a short dated note pointing to the
  later section (also where the change made another finding's description
  stale; its status is not changed there).
- The header gains one line naming the update.
- Where an earlier row and a later section disagree, the later one wins. Every
  earlier row keeps the snapshot it cites.

## 10. Housekeeping

Delete the disposable clone when finished; the writable allowance is fixed.

Never delete the PR branch on merge.

Continuity records — only when the owner has authorized updating them. The
`continuity` branch holds exactly two files, `checkpoint.md` and
`decisions.md`; `.claude/hooks/continuity.sh` prints them at session start as
untrusted history and compares the checkpoint's `` - `main` = `<sha>` `` line
with live `main`. After owner-authorized work changes the state: append an
entry to `decisions.md` (append-only), replace `checkpoint.md`, commit only
those two files, push normally (never force), then re-read both from GitHub.

## What does not belong here

Procedure only. Project facts — crypto layering rules, the canonical contact
hash, sandbox constraints — belong in `CLAUDE.md`. Duplicating them here
recreates the drift that was removed from `CLAUDE.md`.
