#!/usr/bin/env python3
"""Completion gate for the karpathy-review workflow (contract v2).

karpathy-review is a required check. This gate decides it from the agent's
execution record, never from the step outcome or a PR comment alone. It
answers two separate questions:

1. Was the review actually carried out?  Execution succeeded in the default
   permission mode, without permission denials or ExitPlanMode; the agent's
   successful Read calls cover every line of the review methodology; every
   changed file is covered either by a complete, untruncated segment of a
   `git diff` it ran or by Read calls covering every line of the file; and it
   produced one well-formed result block (or identical ones in both the posted
   review and its final answer). Otherwise: exit 1, "review not completed".

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
    summary: <one or two sentences: the overall verdict and its main reason>
    KARPATHY_REVIEW_END

Parsing tolerates Markdown emphasis, code ticks, heading or quote markers and
list bullets around marker lines and keys, and any text after the last block
(the action asks the agent to append job and branch links). It does not
tolerate missing, repeated, unknown or placeholder fields, a block without its
end marker, or two blocks that disagree - within one text or between the posted
review and the final answer. The review text is only parsed for this
structure; nothing in it is executed or followed.

Coverage is established only from tool calls and their outputs in the
execution record, never from what the review says. It depends on two output
formats of Claude Code as pinned by the workflow: Read prefixes every line with
its number and an arrow, and long Bash output is cut with a
"... [N lines truncated] ..." line. If either changes, coverage can no longer be
shown and the gate fails closed.
"""

import json
import os
import re
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


def _canon_text(value):
    """A field value with Markdown emphasis and code ticks removed and
    whitespace collapsed, for comparison only."""
    return " ".join(re.sub(r"[*_`]", "", value).split()).lower()


def canonical(fields):
    """The comparable form of a parsed block: formatting is ignored, every
    field's content is kept."""
    out = {}
    for key, value in fields.items():
        if key == "files":
            out[key] = tuple(sorted({f.strip(_DECORATION) for f in value.split(",") if f.strip(_DECORATION)}))
        elif key in PRINCIPLES:
            verdict, sep, evidence = value.partition("|")
            out[key] = (_canon_text(verdict), sep, _canon_text(evidence))
        else:
            out[key] = _canon_text(value)
    return out


def _result_of(text, source):
    """The single result a text states, or None if it has no block."""
    blocks = [parse_block(b) for b in extract_blocks(text or "")]
    if not blocks:
        return None
    if any(canonical(b) != canonical(blocks[-1]) for b in blocks):
        raise GateError(f"the {source} contains conflicting result blocks")
    return blocks[-1]


def select_result(posted, final_answer):
    """The review's result, from the posted review and/or the final answer.

    If both contain a block they must state the same result field for field;
    neither source is preferred over the other.
    """
    in_post = _result_of(posted, "posted review") if posted is not None else None
    in_final = _result_of(final_answer, "final answer")
    if in_post is not None and in_final is not None:
        a, b = canonical(in_post), canonical(in_final)
        differing = [k for k in FIELDS if a[k] != b[k]]
        if differing:
            raise GateError(
                f"the posted review and the final answer disagree on {', '.join(differing)}"
            )
    result = in_post if in_post is not None else in_final
    if result is None:
        raise GateError(
            f"no complete {RESULT_MARKER} ... {END_MARKER} block in the posted review or the final answer"
        )
    return result


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


def _relative(path, workspace):
    """`path` relative to the workspace, or None if it lies outside it."""
    p = os.path.normpath(str(path))
    if not os.path.isabs(p):
        return p
    rel = os.path.relpath(p, os.path.normpath(workspace))
    return None if rel.startswith("..") else rel


_READ_LINE = re.compile(r"^\s*(\d+)\u2192", re.M)
_TRUNCATED = re.compile(r"^\s*\.\.\. \[\d+ lines truncated\] \.\.\.\s*$")
_DIFF_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)$")
_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_EXTENDED = ("index ", "new file mode ", "deleted file mode ", "old mode ", "new mode ",
             "similarity index ", "dissimilarity index ", "rename from ", "rename to ",
             "copy from ", "copy to ", "--- ", "+++ ")


def read_lines(content):
    """Line numbers a Read output shows: each output line starts with its
    number and an arrow. Content lines cannot forge a number, because the
    real prefix always comes first on the line."""
    return {int(n) for n in _READ_LINE.findall(content)}


def complete_diff_paths(output, workspace=None):
    """Paths whose `git diff` segment in `output` is present in full.

    A segment starts only at a column-0 `diff --git` line; in a unified diff
    every content line starts with a space, `+`, `-` or a backslash, so text in
    a file cannot start one. A segment is complete when every hunk has exactly
    the lines its header declares and nothing else follows before the next
    segment. A truncation marker, a short hunk or any unexpected line makes it
    incomplete.

    One exception, checked against the checkout: Claude Code strips trailing
    whitespace from Bash output, so a diff whose last lines are context lines
    of blank or whitespace-only source lines arrives without them. A final hunk
    left open at the very end of the output is accepted only if
    `trimmed_tail_verified` confirms, from the file in `workspace`, that the
    shown lines are where the header puts them and every missing line is a
    whitespace-only context line.
    """
    complete = set()
    path, ok, hunk = None, False, None  # hunk: [old remaining, new remaining]
    new_line, shown, last_tag = 0, [], None  # final-hunk position and new-side lines

    def close():
        if path is not None and ok and hunk is None:
            complete.add(path)

    for line in output.split("\n"):
        header = _DIFF_HEADER.match(line)
        if header:
            close()
            path, ok, hunk = header.group(2), True, None
            continue
        if path is None or not ok:
            continue
        last_tag = None
        if _TRUNCATED.match(line):
            ok = False
        elif hunk is not None:
            tag = line[:1]
            if tag == " ":
                hunk[0] -= 1
                hunk[1] -= 1
            elif tag == "-":
                hunk[0] -= 1
            elif tag == "+":
                hunk[1] -= 1
            elif tag != "\\":
                ok = False
            if tag in (" ", "+"):
                shown.append((new_line, line[1:]))
                new_line += 1
            last_tag = tag
            if hunk[0] < 0 or hunk[1] < 0:
                ok = False
            elif hunk == [0, 0]:
                hunk = None
        elif _HUNK.match(line):
            m = _HUNK.match(line)
            hunk = [int(m.group(1) or 1), int(m.group(3) or 1)]
            new_line, shown = int(m.group(2)), []
            if hunk == [0, 0]:
                hunk = None
        elif line.startswith(_EXTENDED) or (line.startswith("Binary files ") and line.endswith(" differ")):
            pass
        elif line.startswith("\\"):
            pass  # "\ No newline at end of file" after the last hunk line
        elif line == "":
            pass  # the output's own trailing newline
        else:
            ok = False
    if (path is not None and ok and hunk is not None and workspace is not None
            and last_tag in (" ", "+", "-") and output == output.rstrip()
            and trimmed_tail_verified(workspace, path, hunk, new_line, shown)):
        hunk = None
    close()
    return complete


def trimmed_tail_verified(workspace, path, remaining, next_line, shown):
    """Whether the lines missing from an open final hunk are exactly what
    trailing-whitespace stripping removes: context lines (equal old and new
    remainders) whose source lines, at the positions the hunk header and the
    shown lines fix, contain only whitespace. The shown new-side lines of the
    hunk must match the file, so the positions are established by the source,
    not assumed."""
    old_left, new_left = remaining
    if old_left != new_left or new_left <= 0:
        return False
    rel = _relative(path, workspace)
    if rel is None:
        return False
    full = os.path.join(workspace, rel)
    if os.path.islink(full) or not os.path.isfile(full):
        return False
    with open(full, encoding="utf-8", errors="replace", newline="") as f:
        text = f.read()
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()
    elif next_line + new_left - 1 >= len(lines):
        return False  # git would print "\ No newline at end of file" after it
    if next_line < 1 or next_line + new_left - 1 > len(lines):
        return False
    for number, content in shown:
        if number < 1 or number > len(lines) or lines[number - 1] != content:
            return False
    return all(lines[n - 1].strip() == "" for n in range(next_line, next_line + new_left))


def file_line_count(workspace, relative):
    """Number of lines in a regular file of the checkout, or None."""
    path = os.path.join(workspace, relative)
    if os.path.islink(path) or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        text = f.read()
    return text.count("\n") + (0 if text == "" or text.endswith("\n") else 1)


def _ranges(numbers):
    """Compress sorted numbers into "a-b" ranges."""
    out, start, prev = [], None, None
    for n in sorted(numbers):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = n
    if start is not None:
        out.append(f"{start}-{prev}" if start != prev else str(start))
    return ", ".join(out)


def missing_lines(workspace, relative, seen):
    """Lines of the file not shown by any Read, or None if it cannot be read."""
    total = file_line_count(workspace, relative)
    if total is None:
        return None
    return set(range(1, total + 1)) - seen.get(relative, set())


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

    diffed, seen, posted = set(), {}, []
    for tool_id, call in calls.items():
        out = outputs.get(tool_id)
        if out is None or out.get("is_error"):
            continue
        args = call.get("input") or {}
        if call.get("name") == "Bash" and str(args.get("command", "")).lstrip().startswith("git diff"):
            diffed |= complete_diff_paths(_text_of(out.get("content")), workspace)
        elif call.get("name") == "Read" and args.get("file_path"):
            rel = _relative(args["file_path"], workspace)
            if rel is not None:
                seen.setdefault(rel, set()).update(read_lines(_text_of(out.get("content"))))
        elif call.get("name") == POST_TOOL:
            posted.append(_text_of(args.get("body")))

    gap = missing_lines(workspace, METHODOLOGY, seen)
    if gap is None:
        raise GateError(f"{METHODOLOGY} is not in the checkout")
    if gap and not seen.get(METHODOLOGY):
        raise GateError(f"the agent did not successfully Read {METHODOLOGY}")
    if gap:
        raise GateError(f"successful Read calls do not cover {METHODOLOGY} (missing lines {_ranges(gap)})")

    uncovered = []
    for name in changed:
        if name in diffed:
            continue
        gap = missing_lines(workspace, name, seen)
        if gap is None:
            uncovered.append(f"{name} (no complete diff; not a readable file)")
        elif gap:
            uncovered.append(f"{name} (no complete diff; Read missing lines {_ranges(gap)})")
    if uncovered:
        raise GateError(f"no complete diff or full read in the record for: {'; '.join(uncovered)}")

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
        # the last update is the review.
        result = select_result(posted[-1] if posted else None, final_answer)
        verdicts = validate_result(result, changed)
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
