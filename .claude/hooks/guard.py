#!/usr/bin/env python3
"""PreToolUse guard: turns two CLAUDE.md "never" rules into a confirmation.

CLAUDE.md says a merge needs the owner's instruction naming the PR, and that
deploy and airdrop do not run from the sandbox (`docs/HOME-DEPLOY.md` is a
separate task). Text alone relies on the session remembering it. This hook
answers `ask` for those tool calls, so the harness shows the owner a
confirmation prompt whatever the permission mode:

  - mcp__github__merge_pull_request, mcp__github__enable_pr_auto_merge;
  - a Bash command that runs `gh pr merge`, `solana airdrop`,
    `solana program deploy|upgrade|close`, `anchor deploy|upgrade`,
    `arcium deploy`.

Everything else passes through untouched (no output, exit 0). Input it cannot
parse also answers `ask`: the guard fails closed. It never answers `allow`.

Usage: guard.py               read the hook JSON on stdin
       guard.py --self-test   check the guard itself
"""

import json
import re
import sys

MERGE_TOOLS = {"mcp__github__merge_pull_request", "mcp__github__enable_pr_auto_merge"}
WORD = r"(?:^|[\s;&|()`'\"])"
BASH_RULES = [
    (re.compile(WORD + r"gh\s+pr\s+merge\b"), "merge"),
    (re.compile(WORD + r"solana\s+airdrop\b"), "deploy"),
    (re.compile(WORD + r"solana\s+program\s+(?:deploy|upgrade|close)\b"), "deploy"),
    (re.compile(WORD + r"anchor\s+(?:deploy|upgrade)\b"), "deploy"),
    (re.compile(WORD + r"arcium\s+deploy\b"), "deploy"),
]
REASONS = {
    "merge": "Merge: CLAUDE.md allows it only on the owner's instruction naming this PR. "
    "Owner, confirm only if you asked for this merge.",
    "deploy": "Deploy/airdrop: CLAUDE.md («Окружение») keeps it out of the sandbox; "
    "it is a separate task (docs/HOME-DEPLOY.md). Owner, confirm only if you asked for it.",
    "unparsed": "guard.py could not read the tool call, so it asks instead of guessing.",
}


def decide(event):
    tool = event.get("tool_name", "")
    if tool in MERGE_TOOLS:
        return "merge"
    if tool == "Bash":
        command = (event.get("tool_input") or {}).get("command", "")
        for pattern, kind in BASH_RULES:
            if pattern.search(command):
                return kind
    return None


def answer(kind):
    return json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": REASONS[kind],
        }
    })


def self_test():
    cases = [
        ({"tool_name": "mcp__github__merge_pull_request", "tool_input": {}}, "merge"),
        ({"tool_name": "mcp__github__enable_pr_auto_merge", "tool_input": {}}, "merge"),
        ({"tool_name": "mcp__github__pull_request_read", "tool_input": {}}, None),
        ({"tool_name": "Bash", "tool_input": {"command": "gh pr merge 12 --merge"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "cd x && anchor deploy"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "solana airdrop 2"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "solana program deploy a.so"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "(arcium deploy --x)"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "anchor build && anchor test"}}, None),
        ({"tool_name": "Bash", "tool_input": {"command": "grep -rn 'anchor deploy' docs"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "cargo test --workspace"}}, None),
        ({"tool_name": "Bash", "tool_input": {"command": "solana --version"}}, None),
        ({"tool_name": "Read", "tool_input": {"file_path": "docs/HOME-DEPLOY.md"}}, None),
    ]
    failures = [f"{c} -> {decide(c)!r}, expected {e!r}" for c, e in cases if decide(c) != e]
    for failure in failures:
        print(f"SELF-TEST FAIL {failure}")
    print(f"self-test: {len(cases) - len(failures)}/{len(cases)} cases passed")
    return 1 if failures else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    try:
        event = json.load(sys.stdin)
        kind = decide(event) if isinstance(event, dict) else "unparsed"
    except (ValueError, AttributeError, TypeError):
        kind = "unparsed"
    if kind:
        print(answer(kind))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
