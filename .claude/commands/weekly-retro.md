---
description: Weekly retrospective of the last 7 days. Finds repeated mistakes, failed checks and review-loop problems, and proposes exact rule changes. Applies nothing until the Owner approves.
argument-hint: "[since, default \"7 days ago\"]"
disable-model-invocation: true
---

# /weekly-retro — learn from the last week

Period: `$ARGUMENTS`, or `7 days ago` if no argument is given (written below
as SINCE).

Read-only until the Owner approves. Do not edit, commit or push anything in
steps 1–4.

## 1. Collect evidence (only what exists)

1. Overview: `git log --since="SINCE" --stat --format='%h %ad %s' --date=short`.
2. Detail: `git log --since="SINCE" -p -- . ':(exclude)Cargo.lock' ':(exclude)*.lock' ':(exclude)*.json'`.
   For a large diff, read the commit messages first, then only the diffs
   that matter. Commit messages that start "Correct…", "fix", "revert", or
   that state an earlier claim was wrong, are corrections.
3. QC loops in this clone, if any. Run `python3 .claude/qc/qc.py status <id>`
   for each spec under `<git-dir>/arcium-qc/specs/` (one `<id>.json` each). If
   there are none, say so. Look for FAILED runs, repair rounds and
   ESCALATE_TO_OWNER. This reads only; never write QC state.
4. If GitHub tools are available, use them read-only:
   - pull requests merged or updated in the period, with their review
     comments;
   - failed CI runs on `main` and on those PRs.

   If the tools are not available, say so and continue without them.
5. `docs/SECURITY-FINDINGS.md` rows changed in the period: new findings and
   corrections.

Cite every observation with a SHA, a PR or run number, or a `path:line`.
Claims without a source do not enter the retro.

## 2. Find patterns

Group what you found:
- **repeated mistakes:** the same kind of error fixed more than once (for
  example a failed check type, a review finding class, a wrong claim later
  corrected);
- **review loops:** PRs that needed several review rounds for related
  findings;
- **process friction:** steps that were blocked, redone or done by hand
  repeatedly.

A single incident with no sign of repetition is a one-off.

## 3. Choose a destination for each improvement

| Destination | Use for |
|---|---|
| `CLAUDE.md` | A rule nearly every session needs. Never an inventory: see the F-17 rule at the top of `CLAUDE.md` |
| Review rules: `.claude/skills/engineering-code-review/references/karpathy-review.md` (engineering) or `.claude/skills/arcium-security-review/SKILL.md` (security) | A check reviewers must apply. Add it under a section `## Rules Learned Over Time` in that file; create the section on first use. Do not create a new policy file |
| A specific skill or command | A procedure step belongs to one workflow: edit that `.claude/skills/<skill>/` or `.claude/commands/<cmd>.md` |
| No permanent change | One-off incidents; record them only in the report |

Never propose weakening a security, evidence or Owner-approval rule. Changes
to the cryptographic rules, merge rules or permanent constraints in
`CLAUDE.md` are proposals for the Owner only.

## 4. Propose

Start with the three-line summary from `CLAUDE.md`. Below the separator, for
each proposal give:
- the pattern and its evidence (the sources);
- the destination and why;
- the exact diff, in unified format.

Number the proposals. End with: "Apply which proposals? (numbers, or none)".
Then stop and wait.

## 5. Apply (only after the Owner's answer)

Apply only the proposals the Owner named, exactly as approved. Show
`git diff`, and do not commit or push unless the Owner asks. If the Owner
changes a proposal, apply the changed version and show it again.
