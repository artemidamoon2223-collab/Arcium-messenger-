---
name: repo-change-protocol
description: "Procedures for making repository changes in this project: disposable-clone workflow, scope discipline, evidence standards, PR construction, the mechanics of performing a merge, and the separation of fix PRs from findings-tracker PRs. Describes only HOW these are carried out, never WHEN any of them is permitted. This skill authorizes nothing: every merge requires a separate explicit instruction from the owner, and reading or invoking this skill is not that instruction."
---

# repo-change-protocol

How repository changes are carried out here. Consult it while doing work you
have been asked to do.

## 1. This skill authorizes nothing

The standing boundary in this project: **check with the owner before anything
that writes, installs, or touches git.** This document describes how such work
is performed once instructed. It never establishes that it is permitted.

Merges are the sharpest instance of that boundary, not the whole of it. Every
merge requires a separate explicit instruction naming the PR. Reading,
invoking, or citing this skill is not that instruction — and neither is a
green CI run, nor owner approval of some earlier step.

If any wording below could be read as standing permission, this section
governs and that wording is a defect. Report it.

## 2. Where work happens

Every write goes in a fresh disposable clone of current `main` under `/tmp`.
Verify the clone's HEAD equals the expected main tip before starting.

Never write to the persistent checkout. Read-only inspection of it is fine.

The reason, recorded so it does not get optimised away: the persistent
checkout sits on a stale merged branch with stale remote refs. Writing there
silently produces work against a weeks-old base.

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

In the disposable clone: `cargo test --workspace` and
`cargo clippy --workspace --all-targets`.

On CI, know which checks the diff actually triggers. `bridge-compile-package`
fires on any `crates/**` or `Cargo.toml` change and does not fire on
docs-only diffs. Confirm the checks that ran are green.

## 7. Merge mechanics

How to carry out a merge that has already been instructed:

1. Fresh-read the PR state; record the exact head SHA. If it differs from the
   expected SHA, stop and report.
2. Fresh-read the check state on that exact SHA. Unless every required check
   is success, stop and report.
3. Merge with a normal merge commit. No squash, no rebase, no auto-merge, no
   admin bypass. Keep the branch.
4. Fresh-read afterwards, verifying against a freshly fetched tree rather than
   the merge response.

## 8. Stuck CI is not failing CI

A queue that will not start is an infrastructure condition, not a result. At
most one soft retrigger via an empty commit; note the new head SHA. If it
still will not run, stop and report.

A check that goes red is stop-and-report, with the log.

Slowness never justifies bypassing a check. Never merge on anything other
than all-green.

## 9. Findings-tracker changes

The tracker must never assert a status the code on `main` does not yet
support. The code fix and the tracker update are therefore separate PRs, and
the fix lands first.

A tracker PR greps the document for every mention of the finding and updates
all of them, so the file cannot contradict itself. Split the finding out of
any grouping with still-open items.

Where the change made another finding's description stale, add a
cross-reference note to that entry without changing its status.

## 10. Housekeeping

Delete the disposable clone when finished; the writable allowance is fixed.

Never delete the PR branch on merge.

## What does not belong here

Procedure only. Project facts — crypto layering rules, the canonical contact
hash, sandbox constraints — belong in `CLAUDE.md`. Duplicating them here
recreates the drift that was removed from `CLAUDE.md`.
