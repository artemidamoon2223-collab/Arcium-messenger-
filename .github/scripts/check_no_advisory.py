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
  a `||` whose fallback does not fail              unless allowlisted
  set +e, set +<flags with e>, set +o errexit      unless allowlisted

A fallback fails when it is `exit N` (N > 0), `false`, or a `{ ... }` block
that contains `exit N`. A line ending in `||` is judged by the next line.
Everything else after `||` (`true`, `:`, `echo`, `rc=$?`, a command) needs an
allowlist entry stating why the step's verdict does not depend on it.

Allowlist (advisory_allowlist.txt), one entry per line:
  <path> TAB <the line, stripped> TAB <next non-empty line, stripped> TAB <reason>
The next line pins where the entry applies, so the same text moved elsewhere in
the file is not covered. One entry allows one occurrence; an entry that
matches nothing fails, so the list cannot rot.

Not covered (review still has to catch these): a pipe without `pipefail` under
the default shell, exit codes swallowed inside scripts a step calls, `bash -c`
strings, steps or jobs skipped by `if:` or path filters, and forms not listed
above.

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
SET_RE = re.compile(r"(?:^|[\s;&|(])set\s+(?:\+[a-z]*e[a-z]*\b|\+o\s+errexit\b)")
FAILING_RE = re.compile(r"^\s*(?:\(?\s*exit\s+[1-9]\d*\b|false\b)")


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
    """Whether the text after the last `||` on lines[i] makes the step fail."""
    if not after.strip():
        if i + 1 >= len(lines):
            return False
        return fallback_fails(lines, i + 1, lines[i + 1][1])
    if after.lstrip().startswith("{"):
        depth = 0
        for _, line in lines[i:]:
            segment = after if line is lines[i][1] else line
            if re.search(r"\bexit\s+[1-9]\d*\b", segment):
                return True
            depth += segment.count("{") - segment.count("}")
            if depth <= 0:
                return False
        return False
    return bool(FAILING_RE.match(after))


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
            if "||" in line:
                after = line.rsplit("||", 1)[1]
                if not fallback_fails(lines, i, after):
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
