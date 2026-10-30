---
name: qc-loop
description: "Bounded Builder -> independent Verifier -> independent Reviewer loop for an Owner-authorized Arcium change with a locked qc-spec. The verdict (VERIFIED, FAILED, NOT_VERIFIED, BLOCKED, ESCALATE_TO_OWNER) is computed by .claude/qc/qc.py from evidence it produced itself; at most three repair rounds, then escalation. Reviews use engineering-code-review and arcium-security-review. Authorizes nothing: no commit, push, PR, merge, dispatch or crypto change follows from any state."
disable-model-invocation: true
argument-hint: "<spec-id>"
---

# qc-loop — build, verify, review, within a fixed budget

This skill authorizes nothing. `VERIFIED` means "the locked criteria passed on
this tree and the required reviews are recorded". It is not permission to
commit, push, open a PR, merge or dispatch CI, and it is not a security
proof (`CLAUDE.md`, «Границы доказательств»). Those steps still need their
own explicit Owner instruction.

## Roles

- **Builder** — this session. Implements in the disposable clone. Never
  writes a state, never edits the spec, the QC tool or the evidence.
- **Verifier** — subagent `qc-verifier`, fresh context, no Edit/Write tools
  (its Bash is read-only by instruction, not by enforcement). Runs
  `qc.py run`, which executes every criterion itself and signs the evidence.
- **Reviewer** — subagent `qc-reviewer`, fresh context, no Edit/Write tools.
  Reviews the locked spec as well as the diff, and runs
  `engineering-code-review` and, when `qc.py classify` requires it,
  `arcium-security-review` (plus `mbr-integration` / `android-uniffi-bridge`
  when listed), then records each result block with `qc.py review-record`.

## Loop

1. Precondition: `/qc-spec` locked `$ARGUMENTS`. Read the task and its
   criteria: `python3 .claude/qc/qc.py spec-path $ARGUMENTS` prints the
   spec's path; read that file. Optionally
   `python3 .claude/qc/qc.py activate $ARGUMENTS` to arm the optional hooks
   (only if the Owner enabled them; see below).
2. Build the smallest change that meets the criteria (`engineering-code-review`
   workflow). Stay inside the classes the spec authorizes.
3. Verify: delegate to `qc-verifier` with only the spec id. Do not pass your
   own claims about the result.
4. Read the state it reports, then act:
   - `FAILED` → repair the cause shown in the evidence tails and go to 3.
     Each FAILED run or blocking review consumes one round; after the
     budget (≤ 3 repair rounds) the state becomes `ESCALATE_TO_OWNER`.
   - `NOT_VERIFIED` because a tool, the network, a device or a manual check
     is missing → stop and report it. Do not substitute a weaker check.
   - `NOT_VERIFIED` because the evidence is stale → run the verifier again.
   - `NOT_VERIFIED` with "review pending" → step 5.
   - `BLOCKED` or `ESCALATE_TO_OWNER` → stop and report to the Owner.
5. Review: delegate to `qc-reviewer` with the spec id and the base SHA. A
   CRITICAL/HIGH security finding or an engineering `fail` counts as a failed
   round; repair and return to 3 (new evidence for the new tree is required).
6. Final state: `python3 .claude/qc/qc.py verdict $ARGUMENTS`. End the report
   with exactly the line it printed, `QC_STATE: <state> | <reason>`, and
   `python3 .claude/qc/qc.py deactivate` if you activated it (refused while
   the state is `FAILED`: a loop is not switched off mid-repair; the
   activation also expires by itself after 8 hours).

Never write `QC_STATE: VERIFIED` (or "PASS", "all green") from memory, from a
subagent's prose or from a Markdown file. Only the line `qc.py verdict`
prints counts.

What `VERIFIED` does not establish: that the criteria were adequate (the
Builder wrote them; the reviewer and the Owner judge them), that the
`owner_authorizes` classes match a real Owner instruction (the verdict names
them so the Owner can check), or that the reviews were independent (their
records are signed and must cover every changed path, but a session with
shell access could still write one).

## Report to the Owner

- spec id, base SHA, the classes from `qc.py classify`, `owner_authorizes`;
- per criterion: PASS/FAIL/NOT_VERIFIED with the evidence tail for failures;
- the review result blocks (they are analysis, not proof);
- what was not verified and what would verify it;
- the final `QC_STATE:` line.

## Optional guards (disabled by default)

`.claude/qc/hooks.candidate.json` holds three hook candidates (Stop,
TaskCompleted, PreToolUse). They are not in `.claude/settings.json`. Enabling
them is the Owner's decision: copy the `hooks` block into
`.claude/settings.local.json`. They act only while a loop is activated in
this clone, only ever deny or warn (never allow), and fail open. See the docstring of
`.claude/qc/hooks.py` for exactly what each one checks.
