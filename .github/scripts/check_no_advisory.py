#!/usr/bin/env python3
"""Fail-closed check against known ways a workflow step hides a failure.

CLAUDE.md («Ревью и CI»): a blocking check is never made advisory without the
owner's explicit instruction. This turns the common forms of that into a CI
failure. It reads every non-comment line of

  .github/workflows/**/*.yml|yaml
  .github/actions/**/action.yml|yaml

and fails on:

  continue-on-error with any value but false       always; no allowlist
  shell: <custom template> without -e (e.g. bash {0})   always; no allowlist
  any `||` whose fallback does not fail           unless allowlisted
  set +e, set +<flags with e>, set +o errexit,
  shopt -u -o errexit, trap '... exit 0' EXIT     unless allowlisted

Every `||` on a line is judged. A fallback fails only when it is `exit N`
(N > 0) or `false` with nothing chained after it, or a `{ ... }` block whose
last command (quotes and comments removed) is `exit N`. A line ending in `||`
is judged by the next line. Everything else after `||` (`true`, `:`, `echo`,
`rc=$?`, a command) needs an allowlist entry stating why the step's verdict
does not depend on it. GitHub expressions (`${{ ... }}`) and `if:` values are
not shell and are skipped.

Allowlist (advisory_allowlist.txt), one entry per line:
  <path> TAB <the line, stripped> TAB <next non-empty line, stripped> TAB <reason>
The next line pins where the entry applies, so the same text moved elsewhere in
the file is not covered. One entry allows one occurrence; an entry that
matches nothing fails, so the list cannot rot.

Not covered (review still has to catch these): a pipe without `pipefail` under
the default shell; `!` before a command; `cmd && other` that is not the last
command; `if cmd; then ...; fi`; `eval`; exit codes swallowed inside scripts a
step calls; steps or jobs skipped by `if:` or path filters; and any form not
listed above. This is a denylist of known forms, not a proof.

Usage: check_no_advisory.py              check the repository this file is in
       check_no_advisory.py --self-test  check the checker itself
"""

import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

ALLOWLIST = Path(".github/scripts/advisory_allowlist.txt")
COE_RE = re.compile(r"""["']?continue-on-error["']?\s*:\s*([^,}#]*)""")
SHELL_RE = re.compile(r"^\s*(?:-\s+)?shell\s*:\s*(.*?)\s*(?:#.*)?$")
SET_RE = re.compile(
    r"""(?:^|[\s;&|("'])set\s+(?:\+[a-z]*e[a-z]*\b|\+o\s+errexit\b)"""
    r"|\bshopt\s+-[a-z]*u[a-z]*(?:\s+-o)?\s+errexit\b"
    r"""|\btrap\s+["'][^"']*\bexit\s+0\b"""
)
FAILING_RE = re.compile(r"^\s*\(?\s*(?:exit\s+[1-9]\d*|false)\s*\)?\s*(?:;\s*)?$")
EXPR_RE = re.compile(r"\$\{\{.*?\}\}")
IF_RE = re.compile(r"^\s*(?:-\s+)?if\s*:")
QUOTED_RE = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")


def strip_noise(text):
    """Remove quoted strings and trailing comments, for judging a { } block."""
    text = QUOTED_RE.sub("''", text)
    return re.sub(r"(?:^|\s)#.*$", "", text)


def scanned_files(root):
    files = []
    for pattern in ("*.yml", "*.yaml"):
        files += (root / ".github" / "workflows").rglob(pattern)
    for name in ("action.yml", "action.yaml"):
        files += (root / ".github" / "actions").rglob(name)
    return sorted(set(files))


def code_lines(text):
    """(number, raw line) for every line that is not blank or a whole-line comment."""
    return [
        (n, line)
        for n, line in enumerate(text.splitlines(), 1)
        if line.strip() and not line.strip().startswith("#")
    ]


def fallback_fails(lines, i, after):
    """Whether one `||` fallback (the text after it, up to the next `||`) fails."""
    if not after.strip():
        if i + 1 >= len(lines):
            return False
        return all_fallbacks_fail(lines, i + 1, "||" + shell_text(lines[i + 1][1]))
    if after.lstrip().startswith("{"):
        block, depth = [], 0
        for k, (_, line) in enumerate(lines[i:]):
            segment = strip_noise(after if k == 0 else line)
            block.append(segment)
            depth += segment.count("{") - segment.count("}")
            if depth <= 0:
                break
        body = " ; ".join(block).strip()
        body = body[1:] if body.startswith("{") else body
        body = body[: body.rfind("}")] if "}" in body else body
        commands = [c.strip() for c in re.split(r"[;\n]", body) if c.strip()]
        return bool(commands) and bool(re.fullmatch(r"exit\s+[1-9]\d*", commands[-1]))
    return bool(FAILING_RE.match(strip_noise(after)))


def shell_text(line):
    """The line with GitHub expressions removed; empty for an `if:` key."""
    return "" if IF_RE.match(line) else EXPR_RE.sub("", line)


def all_fallbacks_fail(lines, i, text):
    parts = text.split("||")
    return all(fallback_fails(lines, i, part) for part in parts[1:])


def findings(root):
    """(path, number, stripped line, next stripped line, problem, allowlistable)."""
    out = []
    for path in scanned_files(root):
        rel = path.relative_to(root).as_posix()
        lines = code_lines(path.read_text(encoding="utf-8"))
        for i, (number, line) in enumerate(lines):
            stripped = line.strip()
            following = lines[i + 1][1].strip() if i + 1 < len(lines) else ""
            coe = COE_RE.search(line)
            if coe and coe.group(1).strip().strip("'\"").lower() != "false":
                out.append((rel, number, stripped, following, "continue-on-error makes the step advisory", False))
            shell = SHELL_RE.match(line)
            if shell and "{0}" in shell.group(1) and not re.search(r"(?:^|\s)-[a-z]*e", shell.group(1)):
                out.append((rel, number, stripped, following, "custom shell without -e", False))
            if SET_RE.search(line):
                out.append((rel, number, stripped, following, "errexit turned off", True))
            text = shell_text(line)
            if "||" in text and not all_fallbacks_fail(lines, i, text):
                out.append((rel, number, stripped, following, "|| fallback does not fail", True))
    return out


def load_allowlist(root):
    entries, errors = Counter(), []
    path = root / ALLOWLIST
    if not path.exists():
        return entries, errors
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split("\t")
        if len(parts) != 4 or not parts[0].strip() or not parts[1].strip() or not parts[3].strip():
            errors.append(f"{ALLOWLIST}:{number}: expected <path>TAB<line>TAB<next line>TAB<reason>")
            continue
        entries[tuple(p.strip() for p in parts[:3])] += 1
    return entries, errors


def check(root):
    allowed, errors = load_allowlist(root)
    used = Counter()
    for rel, number, stripped, following, problem, allowlistable in findings(root):
        key = (rel, stripped, following)
        if allowlistable:
            used[key] += 1
            if used[key] <= allowed[key]:
                continue
            errors.append(f"{rel}:{number}: {problem}, not in {ALLOWLIST}: {stripped}")
        else:
            errors.append(f"{rel}:{number}: {problem}: {stripped}")
    for key, count in allowed.items():
        if used[key] < count:
            errors.append(f"{ALLOWLIST}: stale entry ({count - used[key]} unused) in {key[0]}: {key[1]}")
    return errors


def self_test():
    w = ".github/workflows/w.yml"
    cases = {
        "clean": ("run: cargo test\n", "", 0),
        "coe true": ("continue-on-error: true\n", "", 1),
        "coe expression": ("    continue-on-error: ${{ matrix.x }}\n", "", 1),
        "coe flow style": ("- {name: a, continue-on-error: true}\n", "", 1),
        "coe quoted key": ('"continue-on-error": true\n', "", 1),
        "coe false": ("continue-on-error: false\n", "", 0),
        "shell bash {0}": ("shell: bash {0}\n", "", 1),
        "shell bash -e {0}": ("shell: bash -e {0}\n", "", 0),
        "shell bash": ("shell: bash\n", "", 0),
        "or true": ("run: make check || true\n", "", 1),
        "or colon": ("run: make check || :\n", "", 1),
        "or exit 0": ("run: make check || exit 0\n", "", 1),
        "or echo": ("run: make check || echo failed\n", "", 1),
        "or rc": ("run: make || rc=$?\n", "", 1),
        "or block true": ("run: make || { true; }\n", "", 1),
        "or in quotes": ('run: bash -c "make || true"\n', "", 1),
        "or at line end": ("make ||\n  true\n", "", 1),
        "or exit 1": ("run: make || exit 1\n", "", 0),
        "or false": ("run: make || false\n", "", 0),
        "or block exit": ("make || {\n  echo bad\n  exit 1\n}\n", "", 0),
        "or at line end exit": ("make ||\n  exit 2\n", "", 0),
        "set +e": ("  set +e\n", "", 1),
        "set +ex": ("  set +ex\n", "", 1),
        "set +o errexit": ("  set +o errexit\n", "", 1),
        "set -e": ("  set -euo pipefail\n", "", 0),
        "every or": ("run: make || true || exit 1\n", "", 1),
        "false then and": ("run: make || false && true\n", "", 1),
        "exit in quotes": ('make || { echo "exit 1"; }\n', "", 1),
        "exit in comment": ("make || { echo bad; } # exit 1\n", "", 1),
        "exit not last": ("make || { if false; then exit 1; fi; }\n", "", 1),
        "exit 1 in block line": ("make || { echo bad; exit 1; }\n", "", 0),
        "shopt": ("  shopt -uo errexit\n", "", 1),
        "trap exit 0": ("  trap 'exit 0' EXIT\n", "", 1),
        "quoted set": ('  bash -c "set +e; make"\n', "", 1),
        "expression": ("  name: ${{ inputs.a || 'x' }}\n", "", 0),
        "if key": ("  if: failure() || cancelled()\n", "", 0),
        "comment": ("# make || true\n", "", 0),
        "allowed": ("a || true\nb\n", f"{w}\ta || true\tb\tdiag\n", 0),
        "moved": ("a || true\nc\n", f"{w}\ta || true\tb\tdiag\n", 2),
        "stale": ("run: b\n", f"{w}\ta || true\tb\tdiag\n", 1),
        "bad entry": ("run: b\n", f"{w}\ta || true\tb\n", 1),
        "second copy": ("a || true\nb\na || true\nb\n", f"{w}\ta || true\tb\tdiag\n", 1),
        "two entries": ("a || true\nb\na || true\nb\n", f"{w}\ta || true\tb\tdiag\n" * 2, 0),
    }
    failures = []
    for name, (workflow, allow, expected) in cases.items():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "scripts").mkdir(parents=True)
            (root / w).write_text(workflow, encoding="utf-8")
            (root / ALLOWLIST).write_text(allow, encoding="utf-8")
            got = len(check(root))
            if got != expected:
                failures.append(f"{name}: expected {expected} error(s), got {got}")
    for failure in failures:
        print(f"SELF-TEST FAIL {failure}")
    print(f"self-test: {len(cases) - len(failures)}/{len(cases)} cases passed")
    return 1 if failures else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:] == ["--list"]:
        root = Path(__file__).resolve().parents[2]
        for rel, number, stripped, following, problem, ok in findings(root):
            print(f"{rel}\t{stripped}\t{following}\t# {number}: {problem}")
        return 0
    if argv[1:]:
        print(__doc__)
        return 2
    root = Path(__file__).resolve().parents[2]
    errors = check(root)
    for error in errors:
        print(f"::error::{error}")
    if errors:
        return 1
    print("advisory check: no unlisted failure-hiding form found (known forms only; see docstring)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
