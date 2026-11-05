# QC V1 — operating the quality-control loop

How the Owner turns the Arcium QC V1 guards on for one clone, ends a loop,
and recovers when a guard blocks work. The engine is `.claude/qc/qc.py`; the
optional guards are `.claude/qc/hooks.py` with their configuration in
`.claude/qc/hooks.candidate.json`. The design, evidence and limits are in
PR #124.

**Default: off.** `.claude/settings.json` does not reference the hooks. Without
the steps below, nothing in this document affects a session. The guards are
a reliability control against a mistaken or overclaiming agent, not a security
boundary: anything with shell access to the clone can read the evidence key or
delete the loop state.

## Scope of an activation

Two switches, both per clone, both needed before a guard ever acts:

1. **Hooks configured**: the clone has a `.claude/settings.local.json` holding
   the `hooks` block of `.claude/qc/hooks.candidate.json`. This file is
   per-user and untracked; it is never committed.
2. **Loop active**: `qc.py activate <spec-id>` wrote
   `<git-dir>/arcium-qc/active.json`, for at most 8 hours.

With hooks configured but no loop active, every hook exits silently and
nothing is blocked. A loop is active only in the clone (or linked worktree,
which has its own git directory) where it was activated. Other clones, other
worktrees and sessions without the local settings file are not affected.

## Activate (Owner)

Use a dedicated clone of `main` (the QC tool must be committed at the spec's
base), never a clone with unrelated work in progress.

```bash
cd <clone>
# 1. Enable the candidate hooks for this clone only (merges into an existing file).
python3 - <<'EOF'
import json, os
p = ".claude/settings.local.json"
cur = json.load(open(p)) if os.path.exists(p) else {}
cur["hooks"] = json.load(open(".claude/qc/hooks.candidate.json"))["hooks"]
json.dump(cur, open(p, "w"), indent=2)
EOF
# 2. Keep the file out of every commit in this clone.
echo ".claude/settings.local.json" >> "$(git rev-parse --git-path info/exclude)"
```

Then start Claude Code in that clone and run the loop:

- `/qc-spec <id>` writes and locks the acceptance criteria. Lock refuses unless
  HEAD equals the spec's base and the files on disk equal HEAD.
- `python3 .claude/qc/qc.py activate <id>` arms the guards; `/qc-loop` does
  this as its first step when the hooks are enabled.
- `/qc-loop <id>` builds, delegates to `qc-verifier` and `qc-reviewer`, and
  ends with the line `qc.py verdict` printed. The Owner decides from that
  report; VERIFIED authorizes nothing by itself.

Configure the hooks before locking the spec: `.claude/settings.local.json` is
hashed at lock, and any later change to it escalates the loop.

## What the guards do while a loop is active

- **Stop**: a final message claiming `QC_STATE: VERIFIED` while the computed
  verdict is something else is blocked once. An `ESCALATE_TO_OWNER` that the
  message does not report is blocked once. The second time it only warns, so a
  session can always end.
- **TaskCompleted**: a task whose subject contains `[qc]` cannot be completed
  unless the verdict is VERIFIED.
- **PreToolUse**: commits, pushes, merges, PR writes, workflow dispatch and
  deploys are denied, as are edits of the QC tool, its evidence, agent settings
  and `CLAUDE.md`. This holds until the loop is deactivated, VERIFIED included.
- **Fail closed**: if a guard cannot decide, it denies (or blocks the stop
  once). That covers an internal error, its deadline, an unreadable
  activation, hook input it cannot use, and git or `qc.py` failing in that
  clone. It never returns `allow`.

## Deactivate

| Situation | Who | How |
|---|---|---|
| Loop finished, verdict `VERIFIED` | agent or Owner | `python3 .claude/qc/qc.py deactivate` |
| Any other verdict | Owner only | delete the activation from the Owner's own terminal (below) |
| Stop using the guards in this clone | Owner | remove the `hooks` key from `.claude/settings.local.json`, or delete the file, then start a new session |
| Nobody acts | — | the activation expires 8 hours after `activate` |

`deactivate` is refused while the verdict is not VERIFIED, or while the
activation record is unreadable. The agent's own guard denies deleting the
record, so only the Owner can end such a loop:

```bash
rm "$(git rev-parse --absolute-git-dir)/arcium-qc/active.json"
```

This removes only the activation. The specs, runs and reviews stay in
`<git-dir>/arcium-qc/`, so `qc.py status <id>` still shows what happened.

## Recovery

| Symptom | Cause | Action |
|---|---|---|
| Every Bash, Edit or Write is denied with "QC guard could not check this step" | unreadable activation, git or `qc.py` failing in the clone, or a guard timeout | Fix git if it is broken. Otherwise delete `active.json` (above). |
| A commit or push the Owner asked for is denied with "QC loop … is active" | the loop is active, by design | Finish to VERIFIED and run `deactivate`, or delete `active.json`. |
| `deactivate` is refused | the verdict is not VERIFIED | Report the state, then delete `active.json` if the loop should end. |
| A stop is blocked once | the message claimed VERIFIED falsely, or hid an escalation | Report the line `qc.py verdict` prints. |
| `lock` refuses: the files on disk differ from HEAD | untracked or ignored files outside the trusted build directories (`.idea/`, `local.properties`, `.env`, `__pycache__/`) | Move them out of the clone, or use a fresh clone. |
| A verdict is `BLOCKED` because state or records fail integrity | edited, rolled back or partly deleted records | Do not edit them. Inspect with `qc.py status <id>`. A new attempt needs a new spec id, locked on a clean tree at its base. |
| `ESCALATE_TO_OWNER` | repair budget or run cap exhausted, or an owner-gated area without authority | The Owner decides; the loop stays armed until `active.json` is deleted or expires. |

## CI

The `qc-unit` job of Arcium CI runs the deterministic unit tests
(`python3 -B -m unittest discover -s .claude/qc/tests`) and `qc.py self-test`.
Every step is blocking. `.github/scripts/check_qc_test_scope.py` fails the job
if a model-calling test could be discovered there.

Two test files are local only and never run in CI:

- `python3 -B .claude/qc/tests/integration.py`: real cargo builds, several
  minutes;
- `python3 -B .claude/qc/tests/cli_hooks.py --yes-call-the-model --e2e`: real
  Claude Code sessions, which call a model and cost money. Run it only in a
  clone where the cost is acceptable. It creates its own disposable clones.

## Limits

- The guards match command patterns. A script file or an interpreter is not
  inspected.
- `owner_authorizes` in a spec is written by the agent; VERIFIED names those
  classes so the Owner can check them against the instruction.
- Linux with Python 3.12/3.13 is what was tested; macOS is not.
- The full list is in PR #124, "Limitations".
