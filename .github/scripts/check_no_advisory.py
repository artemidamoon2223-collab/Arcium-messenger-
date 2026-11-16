#!/usr/bin/env python3
"""Fail-closed check that no workflow step swallows its own exit code unseen.

CLAUDE.md («Ревью и CI»): a blocking check is never made advisory without the
owner's explicit instruction. This makes that rule a CI check instead of text.
It reads every line of

  .github/workflows/**/*.yml|yaml
  .github/actions/**/action.yml|yaml

and fails on:

  continue-on-error: <anything but false>       always; there is no allowlist
  || true   || :   || exit 0   set +e           unless the exact line is listed,
                                                with a reason, in
                                                advisory_allowlist.txt

The allowlist has one entry per line: `<path>\t<stripped line>\t<reason>`.
One entry allows one occurrence: a second identical line in the same file
needs a second entry. An entry that matches no line also fails, so the list
cannot rot.
Whole-line comments are ignored. A new swallowing line therefore needs a
reviewed allowlist entry in the same PR.

Usage: check_no_advisory.py              check the repository this file is in
       check_no_advisory.py --self-test  check the checker itself
"""

import re
import sys
from collections import Counter
import tempfile
from pathlib import Path

SWALLOW_RE = re.compile(
    r"\|\|\s*(?:true|:)(?=\s|$|\)|;|`|')"
    r"|\|\|\s*exit\s+0\b"
    r"|(?:^|[\s;])set\s+\+e\b"
)
COE_RE = re.compile(r"^\s*(?:-\s+)?continue-on-error\s*:\s*(?P<value>.*?)\s*(?:#.*)?$")
ALLOWLIST = Path(".github/scripts/advisory_allowlist.txt")


def scanned_files(root):
    files = []
    for pattern in ("*.yml", "*.yaml"):
        files += (root / ".github" / "workflows").rglob(pattern)
    for name in ("action.yml", "action.yaml"):
        files += (root / ".github" / "actions").rglob(name)
    return sorted(set(files))


def load_allowlist(root):
    entries, errors = Counter(), []
    path = root / ALLOWLIST
    if not path.exists():
        return entries, errors
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split("\t")
        if len(parts) != 3 or not all(p.strip() for p in parts):
            errors.append(f"{ALLOWLIST}:{number}: expected <path>TAB<line>TAB<reason>")
            continue
        entries[(parts[0].strip(), parts[1].strip())] += 1
    return entries, errors


def check(root):
    allowed, errors = load_allowlist(root)
    used = Counter()
    for path in scanned_files(root):
        rel = path.relative_to(root).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            coe = COE_RE.match(line)
            if coe and coe.group("value").strip("'\"").lower() != "false":
                errors.append(f"{rel}:{number}: continue-on-error makes this step advisory")
            if SWALLOW_RE.search(line):
                key = (rel, stripped)
                used[key] += 1
                if used[key] > allowed[key]:
                    errors.append(
                        f"{rel}:{number}: exit code swallowed and not in {ALLOWLIST}: {stripped}"
                    )
    for key, count in allowed.items():
        if used[key] < count:
            errors.append(
                f"{ALLOWLIST}: stale entry ({count - used[key]} unused) in {key[0]}: {key[1]}"
            )
    return errors


def self_test():
    cases = {
        "clean": ("run: cargo test\n", "", 0),
        "coe true": ("continue-on-error: true\n", "", 1),
        "coe expression": ("    continue-on-error: ${{ matrix.experimental }}\n", "", 1),
        "coe false": ("continue-on-error: false\n", "", 0),
        "or true": ("run: make check || true\n", "", 1),
        "or colon": ("run: make check || :\n", "", 1),
        "or exit 0": ("run: make check || exit 0\n", "", 1),
        "set +e": ("  set +e\n", "", 1),
        "in subshell": ("n=$(grep -c x f || true)\n", "", 1),
        "or truely is a word": ("run: a || trueish\n", "", 0),
        "comment": ("# make || true\n", "", 0),
        "allowed": ("run: a || true\n", "w.yml\trun: a || true\tdiagnostic\n", 0),
        "stale": ("run: b\n", "w.yml\trun: a || true\tdiagnostic\n", 1),
        "bad entry": ("run: b\n", "w.yml\trun: a || true\n", 1),
        "second copy": ("run: a || true\nrun: a || true\n", "w.yml\trun: a || true\tdiag\n", 1),
        "two entries": (
            "run: a || true\nrun: a || true\n",
            "w.yml\trun: a || true\tdiag\nw.yml\trun: a || true\tdiag\n",
            0,
        ),
    }
    failures = []
    for name, (workflow, allow, expected) in cases.items():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "scripts").mkdir(parents=True)
            (root / ".github" / "workflows" / "w.yml").write_text(workflow, encoding="utf-8")
            allow = allow.replace("w.yml", ".github/workflows/w.yml")
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
    if argv[1:]:
        print(__doc__)
        return 2
    root = Path(__file__).resolve().parents[2]
    errors = check(root)
    for error in errors:
        print(f"::error::{error}")
    if errors:
        return 1
    print("advisory check: no unlisted swallowed exit code, no continue-on-error")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
