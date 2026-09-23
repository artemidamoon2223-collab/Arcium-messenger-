#!/usr/bin/env python3
"""Completion gate for the karpathy-review workflow (contract v2).

karpathy-review is a required check. This gate decides it from the agent's
execution record, never from the step outcome or a PR comment alone. It
answers two separate questions:

1. Was the review actually carried out?  Execution succeeded in the default
   permission mode, without permission denials or ExitPlanMode; the agent read
   the review methodology; every changed file appears in a `git diff` it ran or
   in a file it read; and it produced one well-formed result block.
   Otherwise: exit 1, "review not completed".

2. Did the completed review report a substantive failure?  Any principle with
   the verdict "fail": exit 2, "review completed with a FAIL finding". That is
   a finding for the owner to weigh, not an execution failure.

Exit 0 means only that a review was completed without a "fail" verdict. It is
not evidence that the code is correct or secure, and the review's claims about
tests are not test results.

The result block is canonical here and in the workflow prompt; nowhere else.

    KARPATHY_REVIEW_RESULT
    complete: yes|no
    files: <changed paths, comma-separated>
    think_before_coding: pass|warning|fail | <evidence>
    simplicity_first: pass|warning|fail | <evidence>
    surgical_changes: pass|warning|fail | <evidence>
    goal_driven: pass|warning|fail | <evidence>
    unverified: <claims the reviewer could not verify, or none>
    summary: <overall verdict>
    KARPATHY_REVIEW_END

Parsing tolerates Markdown emphasis, code ticks, heading or quote markers and
list bullets around marker lines and keys, and any text after the last block
(the action asks the agent to append job and branch links). It does not
tolerate missing, repeated, unknown or placeholder fields, a block without its
end marker, or two blocks that disagree. The review text is only parsed for
this structure; nothing in it is executed or followed.
"""

import json
import os
import sys

RESULT_MARKER = "KARPATHY_REVIEW_RESULT"
END_MARKER = "KARPATHY_REVIEW_END"
METHODOLOGY = ".claude/skills/engineering-code-review/references/ci-karpathy-review.md"
PRINCIPLES = ("think_before_coding", "simplicity_first", "surgical_changes", "goal_driven")
FIELDS = ("complete", "files") + PRINCIPLES + ("unverified", "summary")
VERDICTS = ("pass", "warning", "fail")
MIN_TEXT = 20
POST_TOOL = "mcp__github_comment__update_claude_comment"

EXIT_OK, EXIT_NOT_COMPLETED, EXIT_FAIL_FINDING = 0, 1, 2


class GateError(Exception):
    """The review was not completed, or its result is unusable."""


# ── Result block ─────────────────────────────────────────────────────────────

_DECORATION = " \t*_`"


def _normalize(line):
    """Strip Markdown decoration: a leading bullet, heading or quote marker,
    and emphasis or code ticks at either end. `>` is only stripped on the left
    so that values ending in `>` keep it."""
    s = line.strip()
    if s.startswith(("- ", "+ ")):
        s = s[2:]
    return s.lstrip("#> \t").strip(_DECORATION)


def extract_blocks(text):
    """Every RESULT ... END block, in order, as lists of inner lines.

    Markers must pair up: a block that is never closed, one opened inside
    another, or an end marker with no block are all malformed, not skipped.
    """
    blocks, current = [], None
    for raw in text.splitlines():
        norm = _normalize(raw)
        if norm == RESULT_MARKER:
            if current is not None:
                raise GateError(f"{RESULT_MARKER} opened again before {END_MARKER}")
            current = []
        elif norm == END_MARKER:
            if current is None:
                raise GateError(f"{END_MARKER} without a preceding {RESULT_MARKER}")
            blocks.append(current)
            current = None
        elif current is not None and raw.strip():
            current.append(raw)
    if current is not None:
        raise GateError(f"{RESULT_MARKER} block is never closed with {END_MARKER}")
    return blocks


def parse_block(lines):
    """Map an inner block to its fields; reject anything but `key: value` lines."""
    fields = {}
    for raw in lines:
        key, sep, value = _normalize(raw).partition(":")
        key = key.strip(_DECORATION).lower()
        if not sep or not key:
            raise GateError(f"malformed result line {raw.strip()!r}")
        if key not in FIELDS:
            raise GateError(f"unknown result field {key!r}")
        if key in fields:
            raise GateError(f"result field {key!r} appears twice")
        fields[key] = value.strip()
    missing = [f for f in FIELDS if f not in fields]
    if missing:
        raise GateError(f"result block is missing {', '.join(missing)}")
    return fields


def select_result(texts):
    """The result of the first text that contains a block.

    Within one text, several complete blocks must agree; the last is used.
    """
    for text in texts:
        blocks = [parse_block(b) for b in extract_blocks(text or "")]
        if not blocks:
            continue
        if any(b != blocks[-1] for b in blocks):
            raise GateError("the review contains conflicting result blocks")
        return blocks[-1]
    raise GateError(
        f"no complete {RESULT_MARKER} ... {END_MARKER} block in the posted review or the final answer"
    )


def _is_placeholder(value):
    v = value.strip()
    return v.startswith("<") and v.endswith(">")


def validate_result(fields, changed):
    """Check field values; return {principle: verdict}."""
    for key, value in fields.items():
        if _is_placeholder(value):
            raise GateError(f"result field {key!r} still holds the template placeholder")
    complete = fields["complete"].strip(_DECORATION).lower()
    if complete == "no":
        raise GateError("the reviewer marked the review incomplete (complete: no)")
    if complete != "yes":
        raise GateError(f"complete must be yes or no, got {fields['complete']!r}")
    files = [f.strip(_DECORATION) for f in fields["files"].split(",") if f.strip(_DECORATION)]
    if len(files) != len(set(files)) or set(files) != set(changed):
        raise GateError(
            "reviewed file list does not match the PR's changed files "
            f"(missing: {sorted(set(changed) - set(files))}, extra: {sorted(set(files) - set(changed))})"
        )
    verdicts = {}
    for key in PRINCIPLES:
        verdict, sep, evidence = fields[key].partition("|")
        verdict = verdict.strip(_DECORATION).lower()
        if verdict not in VERDICTS:
            raise GateError(f"principle {key} has no pass/warning/fail verdict")
        if not sep or len(evidence.strip()) < MIN_TEXT:
            raise GateError(f"principle {key} has no substantive evidence")
        verdicts[key] = verdict
    if not fields["unverified"].strip(_DECORATION):
        raise GateError("unverified must list unverified claims or say none")
    if len(fields["summary"]) < MIN_TEXT:
        raise GateError("overall summary missing")
    return verdicts


# ── Execution record ─────────────────────────────────────────────────────────


def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def _same_path(path, relative, workspace):
    p = os.path.normpath(str(path))
    return p == os.path.normpath(relative) or p == os.path.normpath(os.path.join(workspace, relative))


def check_execution(events, changed, workspace):
    """Validate how the agent ran; return (posted review texts, final answer)."""
    if not isinstance(events, list) or not events:
        raise GateError("execution record is empty or not a list")
    init = next(
        (e for e in events if isinstance(e, dict) and e.get("type") == "system" and e.get("subtype") == "init"),
        None,
    )
    if init is None:
        raise GateError("no session start in execution record")
    if init.get("permissionMode") != "default":
        raise GateError(f"agent ran in permission mode {init.get('permissionMode')!r}, expected 'default'")

    results = [e for e in events if isinstance(e, dict) and e.get("type") == "result"]
    if not results:
        raise GateError("execution ended without a result (interrupted?)")
    result = results[-1]
    if result.get("subtype") != "success" or result.get("is_error") is not False:
        raise GateError(f"execution ended as {result.get('subtype')!r}, is_error={result.get('is_error')!r}")
    if result.get("permission_denials"):
        names = ", ".join(sorted({d.get("tool_name", "?") for d in result["permission_denials"]}))
        raise GateError(f"permission denied during review: {names}")

    calls, outputs = {}, {}
    for e in events:
        if not isinstance(e, dict):
            continue
        for block in (e.get("message") or {}).get("content") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                calls[block.get("id")] = block
            elif block.get("type") == "tool_result":
                outputs[block.get("tool_use_id")] = block
    if any(c.get("name") == "ExitPlanMode" for c in calls.values()):
        raise GateError("agent produced a plan for approval instead of a review")

    diff_text, read_paths, posted = [], set(), []
    for tool_id, call in calls.items():
        out = outputs.get(tool_id)
        if out is None or out.get("is_error"):
            continue
        args = call.get("input") or {}
        if call.get("name") == "Bash" and "git diff" in str(args.get("command", "")):
            diff_text.append(_text_of(out.get("content")))
        elif call.get("name") == "Read" and args.get("file_path"):
            read_paths.add(os.path.normpath(str(args["file_path"])))
        elif call.get("name") == POST_TOOL:
            posted.append(_text_of(args.get("body")))
    diff_text = "\n".join(diff_text)

    if not any(_same_path(p, METHODOLOGY, workspace) for p in read_paths):
        raise GateError(f"the agent did not successfully Read {METHODOLOGY}")

    unseen = []
    for name in changed:
        in_diff = f"diff --git a/{name} b/" in diff_text or f" b/{name}\n" in diff_text
        was_read = any(_same_path(p, name, workspace) for p in read_paths)
        if not (in_diff or was_read):
            unseen.append(name)
    if unseen:
        raise GateError(f"no diff or file read in the record for: {', '.join(unseen)}")

    return posted, str(result.get("result", ""))


# ── Entry point ──────────────────────────────────────────────────────────────


def evaluate(events, changed, workspace, review_outcome="success"):
    """Return (exit code, message, verdicts or None). Never raises GateError."""
    try:
        if review_outcome != "success":
            raise GateError(f"review step outcome={review_outcome or 'unset'}")
        if not changed:
            raise GateError("could not determine the PR's changed files")
        posted, final_answer = check_execution(events, changed, workspace)
        # In tag mode the agent delivers its review by updating the PR comment;
        # the last update is the review, the final answer the fallback.
        texts = ([posted[-1]] if posted else []) + [final_answer]
        verdicts = validate_result(select_result(texts), changed)
    except GateError as e:
        return EXIT_NOT_COMPLETED, f"Karpathy review not completed: {e}. Do NOT add continue-on-error.", None
    summary = ", ".join(f"{k}={verdicts[k]}" for k in PRINCIPLES)
    failed = [k for k in PRINCIPLES if verdicts[k] == "fail"]
    if failed:
        return (
            EXIT_FAIL_FINDING,
            f"Karpathy review completed with a FAIL finding in {', '.join(failed)} ({summary}). "
            "This is a review finding, not an execution failure; owner review required.",
            verdicts,
        )
    return EXIT_OK, f"Karpathy review completed ({summary}). This is not proof of correctness or security.", verdicts


def main():
    path = os.environ.get("EXECUTION_FILE") or ""
    events = None
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                events = json.load(f)
        except (OSError, ValueError) as e:
            events = f"unreadable: {e}"
    changed = []
    changed_path = os.environ.get("CHANGED_FILES") or ""
    if changed_path and os.path.isfile(changed_path):
        with open(changed_path, encoding="utf-8") as f:
            changed = [line.strip() for line in f if line.strip()]
    if events is None:
        code, message, verdicts = EXIT_NOT_COMPLETED, "Karpathy review not completed: no execution record. Do NOT add continue-on-error.", None
    elif isinstance(events, str):
        code, message, verdicts = EXIT_NOT_COMPLETED, f"Karpathy review not completed: execution record {events}. Do NOT add continue-on-error.", None
    else:
        code, message, verdicts = evaluate(
            events,
            changed,
            os.environ.get("GITHUB_WORKSPACE", os.getcwd()),
            os.environ.get("REVIEW_OUTCOME", ""),
        )
    print(("::error::" if code else "") + message)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(f"### Karpathy review gate\n\n{message}\n")
            if verdicts:
                f.write("\n| principle | verdict |\n|---|---|\n")
                f.writelines(f"| {k} | {verdicts[k]} |\n" for k in PRINCIPLES)
    return code


if __name__ == "__main__":
    sys.exit(main())
