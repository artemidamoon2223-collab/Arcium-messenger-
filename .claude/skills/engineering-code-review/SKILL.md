---
name: engineering-code-review
description: "Concrete engineering requirements for making and reviewing changes in this repository: scope discipline, the pre-delivery verification checklist, how claims must be worded, and where things live. Use when writing a non-trivial change, reviewing a diff, or preparing to report a task as done. Describes engineering practice only — it is not a security or cryptographic review, and it authorizes nothing."
---

# engineering-code-review

## Status

Normative for engineering practice in this repository. Does not authorize any
action: writing, installing, or touching git still requires the owner's
instruction, and `repo-change-protocol` describes how such work is carried out.

This skill does **not** cover cryptographic or protocol review. The permanent
crypto rules live in `CLAUDE.md`; changing crypto logic is always a separate
task with its own explicit instruction.

## Purpose

Keep changes small, verified, and honestly described. The failure modes this
guards against, all of which have actually occurred in this repository:

- writing code against an API remembered rather than read;
- widening a diff beyond what was asked;
- reporting a task done without running its verification step;
- describing a result as proven when the evidence does not support it.

## Use when

- Writing a change that touches more than a line or two.
- Reviewing a diff, your own or someone else's.
- About to report a task complete.
- Deciding whether a claim in a PR body or report is supportable.

## Do not use when

- The task is a cryptographic or protocol review — that requires the threat
  classes and constraints in `CLAUDE.md`, and a separate explicit instruction.
- The question is procedural (clone, branch, PR, merge mechanics) — that is
  `repo-change-protocol`.
- The task is the Android UniFFI bridge — that is `android-uniffi-bridge`.

## Workflow

1. **Read before writing.** Find the real signature, value, or API in the
   source or the installed package. Do not write against recollection, and do
   not infer an API from its name. Re-verify any `file:line` before citing it.

2. **Keep the diff to what was asked.** Do not reformat, rename, or "improve"
   adjacent code. Noticing an adjacent defect means reporting it, not fixing it
   in the same change.

3. **Write the minimum that solves the stated problem.** No speculative
   features, no abstraction layers with one caller, no handling for cases that
   cannot occur. If an error branch cannot be reached, do not write it.

4. **Every task has a verification step.** Decide it before starting, and run
   it. If the task cannot be verified in this environment, say so explicitly
   rather than substituting a weaker check silently.

5. **Run the pre-delivery checklist** — see
   `references/delivery-checklist.md`.

6. **Word the claim to match the evidence.** State what the result does *not*
   establish. The evidence rules in `CLAUDE.md` ("Границы доказательств")
   apply to every report, PR body, and commit message.

## Constraints

- Compilation success does not prove runtime correctness, security, or protocol
  correctness. A green CI check proves only that the job ran to completion.
- Your own summary of earlier work is not evidence.
- Never weaken a `must`, `must not`, `only`, or `never` from an existing rule
  when restating it.
- Do not silently resolve a conflict between two instructions: preserve both,
  report the conflict, and keep the stricter constraint.
- Do not present experimental or stub code as production-ready.
- Long code blocks are hard to read on the reviewer's device — split them.

## References

- `references/delivery-checklist.md` — the checklist to run before reporting a
  task done.
- `references/repo-map.md` — where things live, and how to re-derive the map
  instead of trusting it.
- `references/karpathy-origin.md` — the original external principles this
  skill was derived from. Optional background, non-normative.
