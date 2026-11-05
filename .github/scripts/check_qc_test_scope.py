#!/usr/bin/env python3
"""Keep model-calling QC tests out of CI (CLAUDE.md: no LLM calls in CI).

CI runs `python3 -B -m unittest discover -s .claude/qc/tests`, which loads
every file matching unittest's default pattern `test*.py`. Two files in that
directory must never be loaded there:

  cli_hooks.py    starts nested `claude -p` sessions, which call a model;
  integration.py  runs real cargo builds; local and opt-in.

This script exits 0 only when:

  1. the directory exists and at least one file matches `test*.py`;
  2. neither cli_hooks.py nor integration.py matches `test*.py` (a rename
     would pull it into CI);
  3. no file that matches imports or runs either of them, starts a `claude`
     process, or names a model API key or endpoint.

It is a guard against mistakes in the test layout, not a sandbox: a test can
still reach the network through code this scan does not recognise. The
verdict is the exit status.

Usage: check_qc_test_scope.py              check this repository
       check_qc_test_scope.py --self-test  check the checker itself
"""

import fnmatch
import os
import re
import sys
import tempfile

PATTERN = "test*.py"  # unittest discover's default
LOCAL_ONLY = ("cli_hooks.py", "integration.py")
FORBIDDEN = [
    (re.compile(r"\b(import|from)\s+(cli_hooks|integration)\b"), "imports a local-only test module"),
    (re.compile(r"""["']claude["']\s*,\s*["']-p["']|["']claude\s+-p\b"""), "starts `claude -p` (a model call)"),
    (re.compile(r"--yes-call-the-model"), "passes the model-call opt-in"),
    (re.compile(r"ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|api\.anthropic\.com"), "names a model API key or endpoint"),
]


def problems(test_dir):
    if not os.path.isdir(test_dir):
        return ["%s does not exist" % test_dir]
    found, out = [], []
    for name in sorted(os.listdir(test_dir)):
        if not fnmatch.fnmatch(name, PATTERN):
            continue
        found.append(name)
        if name in LOCAL_ONLY:
            out.append("%s matches %s and would run in CI" % (name, PATTERN))
        with open(os.path.join(test_dir, name), encoding="utf-8") as f:
            text = f.read()
        for rx, why in FORBIDDEN:
            if rx.search(text):
                out.append("%s %s" % (name, why))
    for name in LOCAL_ONLY:
        if fnmatch.fnmatch(name, PATTERN):
            out.append("%s matches %s" % (name, PATTERN))
    if not found:
        out.append("no %s files in %s: CI would run no QC tests" % (PATTERN, test_dir))
    return out


def self_test():
    cases = {
        "clean": ({"test_ok.py": "import unittest\n", "cli_hooks.py": "subprocess.run(['claude', '-p', 'x'])\n"}, 0),
        "empty": ({"cli_hooks.py": "x = 1\n"}, 1),
        "renamed": ({"test_cli_hooks.py": "x = 1\n", "test_cli.py": "import cli_hooks\n"}, 1),
        "model call": ({"test_x.py": "subprocess.run(['claude', '-p', 'hi'])\n"}, 1),
        "opt-in": ({"test_x.py": "argv = ['--yes-call-the-model']\n"}, 1),
        "api key": ({"test_x.py": "os.environ['ANTHROPIC_API_KEY']\n"}, 1),
    }
    bad = []
    for label, (files, want_problems) in cases.items():
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                with open(os.path.join(d, name), "w") as f:
                    f.write(text)
            got = problems(d)
            if bool(got) != bool(want_problems):
                bad.append("%s: expected %s, got %s" % (label, "problems" if want_problems else "none", got))
    if not problems(os.path.join(tempfile.gettempdir(), "qc-scope-missing-dir-%d" % os.getpid())):
        bad.append("a missing directory passed")
    for b in bad:
        print("SELF-TEST FAILED: %s" % b)
    print("self-test: %d case(s) failed" % len(bad))
    return 1 if bad else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    out = problems(os.path.join(root, ".claude", "qc", "tests"))
    for p in out:
        print("::error::%s" % p)
    if not out:
        print("QC test scope OK: only deterministic %s files are discovered" % PATTERN)
    return 1 if out else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
