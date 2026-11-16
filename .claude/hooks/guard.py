#!/usr/bin/env python3
"""PreToolUse guard: asks the owner before known merge and deploy paths.

CLAUDE.md says a merge needs the owner's instruction naming the PR, and that
deploy and airdrop do not run from the sandbox (`docs/HOME-DEPLOY.md` is a
separate task). Text alone relies on the session remembering it. This hook
answers `ask` for the known forms of those calls:

  - mcp__github__merge_pull_request, mcp__github__enable_pr_auto_merge;
  - mcp__github__push_files, create_or_update_file, delete_file when the
    branch is main or master (a direct write to main);
  - Bash: `gh ... pr merge`, `gh api` calls with `/merge`, `/merges`,
    `mergePullRequest` or `git/refs/heads/main|master`, any command naming
    api.github.com with one of those, `git ... push` naming main or master;
    `solana ... airdrop`, `solana ... program deploy|upgrade|close`,
    `anchor ... deploy|upgrade`, `arcium ... deploy`, a devnet or mainnet
    cluster (`--provider.cluster`, `-u`/`--url devnet|mainnet`), `test:devnet`,
    and any command naming api.devnet.solana.com or api.mainnet-beta.solana.com.
  - MCP file writes with no branch given also ask.

It is a denylist of known forms, not a sandbox: a command built another way
(a script, an alias, `eval`, a bare `git push` while on main) is not seen, and
the rules in CLAUDE.md still apply. Everything else passes through (no output, exit 0). Unreadable input
answers `ask`. If python is missing or the script fails, the command in
`.claude/settings.json` prints the same `ask`; a hook killed by its timeout
gets no answer from either. It never answers `allow`.
Whether the harness shows the prompt in every permission mode is decided by
Claude Code, not here.

Usage: guard.py               read the hook JSON on stdin
       guard.py --self-test   check the guard itself
"""

import json
import re
import sys

MERGE_TOOLS = {"mcp__github__merge_pull_request", "mcp__github__enable_pr_auto_merge"}
WRITE_TOOLS = {"mcp__github__push_files", "mcp__github__create_or_update_file", "mcp__github__delete_file"}
START = r"(?:^|[\s;&|()`'\"])"
ARGS = r"[^;&|\n]*?"
MERGE_API = r"(?:/merges?\b|mergePullRequest|git/refs/heads/(?:main|master)\b)"
BASH_RULES = [
    (re.compile(START + r"(?:\S*/)?gh\b" + ARGS + r"\bpr\s+merge\b"), "merge"),
    (re.compile(START + r"(?:\S*/)?gh\b" + ARGS + r"\bapi\b" + ARGS + MERGE_API), "merge"),
    (re.compile(r"api\.github\.com" + ARGS + MERGE_API), "merge"),
    (re.compile(START + r"git\b" + ARGS + r"\bpush\b" + ARGS + r"(?:[\s:/]|^)(?:main|master)\b"), "merge"),
    (re.compile(START + r"solana\b" + ARGS + r"\bairdrop\b"), "deploy"),
    (re.compile(START + r"solana\b" + ARGS + r"\bprogram\s+(?:deploy|upgrade|close)\b"), "deploy"),
    (re.compile(START + r"anchor\b" + ARGS + r"\b(?:deploy|upgrade)\b"), "deploy"),
    (re.compile(START + r"arcium\b" + ARGS + r"\bdeploy\b"), "deploy"),
    (re.compile(r"--provider\.cluster[\s=]+(?:devnet|mainnet)"), "deploy"),
    (re.compile(START + r"solana\b" + ARGS + r"(?:-u|--url)[\s=]+(?:d|m|devnet|mainnet-beta|mainnet)\b"), "deploy"),
    (re.compile(r"\btest:devnet\b"), "deploy"),
    (re.compile(r"api\.(?:devnet|mainnet-beta)\.solana\.com"), "deploy"),
]
REASONS = {
    "merge": "Merge or write to main: CLAUDE.md allows a merge only on the owner's instruction "
    "naming the PR. Owner, confirm only if you asked for this.",
    "deploy": "Deploy/airdrop/devnet: CLAUDE.md («Окружение») keeps it out of the sandbox; "
    "it is a separate task (docs/HOME-DEPLOY.md). Owner, confirm only if you asked for it.",
    "unparsed": "guard.py could not read the tool call, so it asks instead of guessing.",
}


def decide(event):
    tool = event.get("tool_name", "")
    if tool in MERGE_TOOLS:
        return "merge"
    if tool in WRITE_TOOLS:
        branch = str((event.get("tool_input") or {}).get("branch", "")).strip()
        return "merge" if branch in ("", "main", "master", "refs/heads/main", "refs/heads/master") else None
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
        ({"tool_name": "Bash", "tool_input": {"command": "gh -R o/r pr merge 12"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "/usr/bin/gh pr merge 1"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "gh api -X PUT repos/o/r/pulls/12/merge"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "gh api graphql -f query='mutation{mergePullRequest}'"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "git push origin HEAD:main"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "git push -u origin main"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "git push -u origin fix/x"}}, None),
        ({"tool_name": "Bash", "tool_input": {"command": "git push origin continuity"}}, None),
        ({"tool_name": "Bash", "tool_input": {"command": "git push origin docs/maintenance"}}, None),
        ({"tool_name": "Bash", "tool_input": {"command": "git fetch origin main"}}, None),
        ({"tool_name": "Bash", "tool_input": {"command": "solana -u devnet airdrop 2"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "solana --url devnet program deploy x.so"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "solana config set --url devnet"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "anchor test --provider.cluster devnet"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "cd arcium-psi/tests && npm run test:devnet"}}, "deploy"),
        ({"tool_name": "mcp__github__push_files", "tool_input": {"branch": "main"}}, "merge"),
        ({"tool_name": "mcp__github__create_or_update_file", "tool_input": {"branch": "fix/x"}}, None),
        ({"tool_name": "mcp__github__delete_file", "tool_input": {"branch": "master"}}, "merge"),
        ({"tool_name": "mcp__github__create_or_update_file", "tool_input": {}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "gh api repos/o/r/merges -f base=main"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "gh api -X PATCH repos/o/r/git/refs/heads/main"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "curl -X PUT https://api.github.com/repos/o/r/pulls/1/merge"}}, "merge"),
        ({"tool_name": "Bash", "tool_input": {"command": "SOLANA_RPC_URL=https://api.devnet.solana.com npm test"}}, "deploy"),
        ({"tool_name": "Bash", "tool_input": {"command": "gh api repos/o/r/pulls/1"}}, None),
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
    except Exception:  # noqa: BLE001 - any failure to read the call asks
        kind = "unparsed"
    if kind:
        print(answer(kind))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
