#!/usr/bin/env python3
"""Fail-closed check that every action a workflow runs is immutably pinned.

A tag (`@v4`, `@v1.2.3`) or a branch (`@main`) can be moved upstream to point
at different code; a full commit SHA cannot (F-5). This reads every `uses:` in

  .github/workflows/**/*.yml|yaml      (workflows; job-level reusable
                                        workflows and step-level actions)
  .github/actions/**/action.yml|yaml   (local composite actions)
  any other local action a scanned file refers to

and accepts only:

  ./path                                  a local action or workflow that exists
  owner/repo[/path]@<40 lowercase hex> # vX.Y.Z
                                          an external action or reusable
                                          workflow, with its release on the line
  docker://image@sha256:<64 lowercase hex>

Anything else exits non-zero, including a `uses:` line this script cannot
parse (flow style, quoted key, value on the next line, `uses:` in a comment
after other text): it never skips one. Only whole-line comments are ignored.
New workflow files are picked up by the glob; nothing lists them.

Usage: check_action_pins.py              check the repository this file is in
       check_action_pins.py --self-test  check the checker itself
"""

import re
import sys
import tempfile
from pathlib import Path

SHA_RE = re.compile(r"[0-9a-f]{40}")
EXTERNAL_RE = re.compile(r"([A-Za-z0-9-]+/[A-Za-z0-9._-]+)(/[^@\s]+)?@([^@\s]*)")
DOCKER_RE = re.compile(r"docker://[^@\s]+@sha256:[0-9a-f]{64}")
VERSION_RE = re.compile(r"v\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?(\s.*)?")
# The one form a `uses:` line may take: optional list dash, the key, a plain or
# quoted value, an optional comment after whitespace.
USES_RE = re.compile(
    r"\s*(?:-\s+)?uses\s*:"
    r"(?:\s+(?:\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)'|(?P<bare>[^\s\"'#]\S*)))?"
    r"(?:\s+#(?P<comment>.*))?\s*"
)
# Any line where `uses` may be a key, in whatever YAML form.
MAYBE_USES_RE = re.compile(r"(?:^|[\s{,\-])[\"']?uses[\"']?\s*:")


def check_value(value, comment, root):
    """(kind, error or None, local path or None) for one `uses:` value."""
    if value.startswith("./"):
        target = (root / value[2:]).resolve()
        if not target.is_relative_to(root.resolve()):
            return "local", "local path leaves the repository", None
        if value.endswith((".yml", ".yaml")):
            return "local", None if target.is_file() else "local workflow not found", None
        for name in ("action.yml", "action.yaml"):
            if (target / name).is_file():
                return "local", None, target / name
        return "local", "local action not found (no action.yml or action.yaml)", None
    if value.startswith("docker://"):
        if DOCKER_RE.fullmatch(value):
            return "docker", None, None
        return "docker", "docker image is not pinned by @sha256:<64 hex> digest", None
    m = EXTERNAL_RE.fullmatch(value)
    if not m:
        return "external", "not a local path, owner/repo@ref or docker:// reference", None
    ref = m.group(3)
    if not ref:
        return "external", "missing ref after @", None
    if not SHA_RE.fullmatch(ref):
        if re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            return "external", "commit SHA must be lowercase", None
        if re.fullmatch(r"[0-9a-fA-F]{7,64}", ref):
            return "external", f"{len(ref)}-character SHA; a full SHA has 40", None
        return "external", f"mutable ref @{ref} (tag or branch); pin a full commit SHA", None
    if comment is None or not VERSION_RE.fullmatch(comment.strip()):
        return "external", "pinned SHA needs its release as a comment: # vX.Y.Z", None
    return "external", None, None


def check_line(line, root):
    """None if `line` has no `uses:` key, else (kind, error or None, local path)."""
    if line.lstrip().startswith("#") or not MAYBE_USES_RE.search(line):
        return None
    m = USES_RE.fullmatch(line)
    if not m:
        return "unknown", "cannot parse this uses: line", None
    value = m.group("dq") if m.group("dq") is not None else m.group("sq")
    if value is None:
        value = m.group("bare")
    if not value:
        return "unknown", "uses: without a value on the same line", None
    return check_value(value, m.group("comment"), root)


def scan(root):
    """(errors, counts) for every workflow and local action under `root`."""
    root = root.resolve()
    github = root / ".github"
    queue = sorted(p for ext in ("yml", "yaml") for p in (github / "workflows").rglob(f"*.{ext}"))
    if not queue:
        return [f"{github / 'workflows'}: no workflow files found"], {}
    queue += sorted(p for ext in ("yml", "yaml") for p in (github / "actions").rglob(f"action.{ext}"))
    seen, errors = set(), []
    counts = {"files": 0, "external": 0, "local": 0, "docker": 0}
    while queue:
        path = queue.pop(0).resolve()
        if path in seen:
            continue
        seen.add(path)
        counts["files"] += 1
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            result = check_line(line, root)
            if result is None:
                continue
            kind, error, local = result
            if error:
                errors.append(f"{path.relative_to(root)}:{n}: {error}: {line.strip()}")
            else:
                counts[kind] += 1
            if local is not None:
                queue.append(local)
    return errors, counts


def self_test():
    sha = "11d5960a326750d5838078e36cf38b85af677262"
    digest = "a" * 64
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".github/workflows").mkdir(parents=True)
        (root / ".github/actions/local").mkdir(parents=True)
        (root / ".github/actions/local/action.yml").write_text("runs:\n  using: composite\n")
        (root / ".github/workflows/ok.yml").write_text(f"steps:\n  - uses: actions/checkout@{sha} # v4.4.0\n")
        cases = [
            (f"      - uses: actions/checkout@{sha} # v4.4.0", True),
            (f"        uses: actions/checkout@{sha}   # v4.4.0", True),
            (f'      - uses: "actions/checkout@{sha}" # v4.4.0', True),
            (f"      - uses: 'actions/checkout@{sha}' # v4.4.0", True),
            (f"    uses: org/repo/.github/workflows/ci.yml@{sha} # v1.0.0", True),
            (f"      - uses: org/repo/sub/dir@{sha} # v2.0.0-rc.1", True),
            ("        uses: ./.github/actions/local", True),
            ("        uses: ./.github/workflows/ok.yml", True),
            (f"      - uses: docker://alpine@sha256:{digest}", True),
            ("      - name: build  # this step uses: nothing", False),
            ('      - {name: "a #b", uses: actions/checkout@v4}', False),
            ("      # - uses: actions/checkout@v4", None),
            ("      - run: echo hi", None),
            ("      - uses: actions/checkout@v4", False),
            ("      - uses: actions/checkout@v4 # v4.4.0", False),
            ("      - uses: actions/checkout@v1.2.3", False),
            ("      - uses: actions/checkout@main", False),
            ("      - uses: actions/checkout@master", False),
            ("      - uses: actions/checkout@11d5960", False),
            (f"      - uses: actions/checkout@{sha[:39]} # v4.4.0", False),
            (f"      - uses: actions/checkout@{sha}a # v4.4.0", False),
            (f"      - uses: actions/checkout@{sha.upper()} # v4.4.0", False),
            (f"      - uses: actions/checkout@{sha}", False),
            (f"      - uses: actions/checkout@{sha} # latest", False),
            (f"      - uses: actions/checkout@{sha}#v4.4.0", False),
            ("      - uses: actions/checkout", False),
            ("      - uses: actions/checkout@", False),
            ("      - uses: checkout@" + sha + " # v4.4.0", False),
            ("      - uses: ${{ matrix.action }}", False),
            ("      - uses: *anchor", False),
            ("      - uses: docker://alpine:3", False),
            ("      - uses: docker://alpine", False),
            ("      - uses: docker://alpine@sha256:abc", False),
            ("        uses: ./.github/actions/missing", False),
            ("        uses: ../outside", False),
            ("        uses: ./../outside", False),
            ("      - uses:", False),
            ("      - {uses: actions/checkout@v4}", False),
            ('      - "uses": actions/checkout@v4', False),
            ("      - uses: actions/checkout@v4 extra", False),
        ]
        failed = []
        for line, ok in cases:
            result = check_line(line, root)
            got = None if result is None else result[1] is None
            if got is not ok:
                failed.append(f"expected {ok}, got {got}: {line.strip()}")

        # A workflow nobody lists is scanned, and a local action is followed.
        errors, counts = scan(root)
        if errors or counts["files"] != 2 or counts["external"] != 1:
            failed.append(f"clean tree: {errors} {counts}")
        (root / ".github/workflows/new.yaml").write_text(
            "jobs:\n  x:\n    steps:\n      - uses: ./.github/actions/local\n      - uses: someone/thing@v1\n"
        )
        errors, counts = scan(root)
        if len(errors) != 1 or "new.yaml:5" not in errors[0] or counts["local"] != 1:
            failed.append(f"new workflow: {errors} {counts}")
        (root / ".github/actions/local/action.yml").write_text(
            "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n"
        )
        errors, _ = scan(root)
        if not any("actions/local/action.yml:4" in e for e in errors):
            failed.append(f"composite action not scanned: {errors}")
        empty = root / "empty"
        empty.mkdir()
        if not scan(empty)[0]:
            failed.append("a tree without workflows passed")
    for f in failed:
        print(f"SELF-TEST FAIL: {f}")
    print(f"self-test: {len(cases)} line cases + 4 tree cases, {len(failed)} failed")
    return 1 if failed else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:]:
        print(__doc__)
        return 2
    root = Path(__file__).resolve().parents[2]
    errors, counts = scan(root)
    for e in errors:
        print(f"ERROR: {e}")
    print(
        f"{counts.get('files', 0)} files: {counts.get('external', 0)} pinned external, "
        f"{counts.get('local', 0)} local, {counts.get('docker', 0)} docker; {len(errors)} errors"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
