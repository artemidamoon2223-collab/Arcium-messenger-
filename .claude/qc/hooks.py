#!/usr/bin/env python3
"""Optional QC guards for Claude Code hooks. Candidates, disabled by default.

They run only if an Owner adds .claude/qc/hooks.candidate.json to
.claude/settings.local.json, and even then do nothing unless a QC loop was
activated in this clone (qc.py activate <id>, which expires after 8 hours).

  stop             Stop: refuses a final message that claims
                   "QC_STATE: VERIFIED" while qc.py's verdict is something
                   else, or that hides an ESCALATE_TO_OWNER. Never blocks when
                   stop_hook_active is true, so it adds at most one turn; a
                   claim still false then is shown to the person as a warning.
  task-completed   TaskCompleted: a task whose subject carries "[qc]" cannot be
                   marked completed unless the verdict is VERIFIED.
  pre-tool         PreToolUse: denies owner-only operations (commit, push,
                   merge, PR writes, workflow dispatch, deploy) and edits of the
                   QC tool, its evidence under .git/, agent settings and
                   CLAUDE.md while the loop is active. Pattern matching on
                   commands is a guard against mistakes, not a sandbox.

They only ever deny or stay silent: no output here grants a permission. Any
internal error exits 0 silently (fail-open) so a broken guard cannot trap a
session; Claude Code's own permission mode still applies.
"""

import json
import os
import re
import sys

# No __pycache__ in the working tree: it would change the tree fingerprint.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qc  # noqa: E402

CLAIM_RE = re.compile(r"QC_STATE:\s*(VERIFIED|FAILED|NOT_VERIFIED|BLOCKED|ESCALATE_TO_OWNER)\b")

GIT_OWNER_ONLY = re.compile(
    r"(^|[\s;&|(`$/\\\"'])git[\"']?\s+(?:-C\s+\S+\s+|-c\s+\S+\s+|--\S+\s+)*"
    r"(commit|push|merge(?!-)|rebase|tag(?!\s+(-l|--list)\b)|cherry-pick|am|revert|update-ref|filter-branch|"
    r"filter-repo|replace)\b")
OTHER_OWNER_ONLY = re.compile(
    r"(^|[\s;&|(`$/\\\"'])(gh\s+(pr\s+(?!(view|list|diff|checks|status)\b)|workflow\s+(run|enable|disable)\b|"
    r"release\s+(create|delete|edit|upload)\b|api\b|repo\s+(create|delete|edit|fork|rename)\b|"
    r"run\s+(rerun|cancel|delete)\b)|"
    r"(anchor|arcium)\s+deploy\b|solana\s+(airdrop|program\s+deploy|deploy)\b)")
MCP_WRITE = re.compile(
    r"^mcp__github__(merge_|create_|update_|delete_|push_|fork_|enable_|disable_|add_|resolve_|unresolve_|"
    r"request_|actions_run_trigger|issue_write|sub_issue_write|pull_request_review_write)")
PROTECTED = re.compile(r"(^|/)(CLAUDE\.md|\.git/|\.claude/(settings[^/]*\.json|qc/|hooks/|agents/|skills/))")
BASH_WRITES_PROTECTED = re.compile(
    r"((?<![0-9&])>(?!&)|\btee\b|\bsed\s+-i|\bmv\b|\bcp\b|\brm\b|\bchmod\b|\btruncate\b|"
    r"\bpython3?\s+-c\b|\bperl\s+-\w*[pie]|\bgit\s+(checkout|restore|reset|clean|stash)\b).*"
    r"(CLAUDE\.md|\.claude/(settings|qc|hooks|agents|skills)|arcium-qc)")


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))


def main(event, data):
    root = qc.repo_root(data.get("cwd") or None)
    sid = qc.active_loop(root)
    if sid is None:
        return 0  # no active QC loop in this clone: the guards do nothing

    if event == "stop":
        msg = data.get("last_assistant_message") or ""
        claims = CLAIM_RE.findall(msg)
        if data.get("stop_hook_active"):
            # Never block twice. A claim that is still false is shown to the
            # person instead, so it cannot pass unnoticed.
            if "VERIFIED" in claims:
                state, why = qc.verdict(root, sid)
                if state != "VERIFIED":
                    print(json.dumps({"systemMessage": "QC WARNING: the final message claims QC_STATE: VERIFIED, "
                                      "but qc.py verdict for %s is %s (%s)." % (sid, state, why)}))
            return 0
        state, why = qc.verdict(root, sid)
        if "VERIFIED" in claims and state != "VERIFIED":
            print(json.dumps({"decision": "block", "reason":
                              "QC loop %s: you reported QC_STATE: VERIFIED, but qc.py verdict is %s (%s). "
                              "Report the computed state; never write VERIFIED yourself." % (sid, state, why)}))
        elif state == "ESCALATE_TO_OWNER" and claims and claims[-1] not in ("ESCALATE_TO_OWNER", "BLOCKED"):
            print(json.dumps({"decision": "block", "reason":
                              "QC loop %s is ESCALATE_TO_OWNER (%s). Stop repairing and report that state "
                              "to the Owner." % (sid, why)}))
        return 0

    if event == "task-completed":
        subject = "%s %s" % (data.get("task_subject", ""), data.get("task_description", ""))
        if "[qc]" not in subject:
            return 0
        state, why = qc.verdict(root, sid)
        if state != "VERIFIED":
            sys.stderr.write("QC loop %s: this task cannot be completed while the verdict is %s (%s).\n"
                             % (sid, state, why))
            return 2
        return 0

    if event == "pre-tool":
        tool = data.get("tool_name", "")
        ti = data.get("tool_input") or {}
        if tool == "Bash":
            cmd = str(ti.get("command", ""))
            if GIT_OWNER_ONLY.search(cmd) or OTHER_OWNER_ONLY.search(cmd):
                deny("QC loop %s is active: this is an owner-only operation (commit/push/merge/PR/dispatch/"
                     "deploy). Report to the Owner instead." % sid)
            elif BASH_WRITES_PROTECTED.search(cmd):
                deny("QC loop %s is active: the QC tool, hooks, agent settings and CLAUDE.md are not "
                     "edited during a loop." % sid)
        elif MCP_WRITE.match(tool):
            deny("QC loop %s is active: GitHub write operations are owner-only." % sid)
        elif tool in ("Edit", "Write", "NotebookEdit", "MultiEdit"):
            path = str(ti.get("file_path") or ti.get("notebook_path") or "")
            if PROTECTED.search(path):
                deny("QC loop %s is active: %s is part of the QC/agent control plane." % (sid, path))
        return 0
    return 0


if __name__ == "__main__":
    try:
        raw = sys.stdin.read(1 << 20)
        payload = json.loads(raw) if raw.strip() else {}
        sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "", payload))
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001 - fail open, never trap a session
        sys.exit(0)
