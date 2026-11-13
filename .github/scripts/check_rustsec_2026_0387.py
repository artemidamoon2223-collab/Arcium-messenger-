#!/usr/bin/env python3
"""Fail-closed reachability guard for the RUSTSEC-2026-0387 ignore.

.cargo/audit.toml ignores RUSTSEC-2026-0387 (crypto-bigint < 0.7.6, timing
variability) because crypto-bigint 0.5.5 is only a Cargo.lock entry: ssh-key
0.6.7 lists p256/p384/p521 as optional dependencies, and nothing in this
workspace turns them on. Cargo.lock records optional dependencies whether or
not a feature activates them, so cargo-audit reports a crate that is never
compiled. This script makes that ignore conditional on it staying true.

It exits 0 only when all of the following hold:

  1. Cargo.lock lists crypto-bigint exactly once, at 0.5.5. Absent means the
     ignore is obsolete and must be removed; any other version set means the
     ignore must be reviewed again before it may cover it.
  2. `cargo tree --locked` succeeds for every target in TARGETS and every
     feature mode in FEATURE_MODES, over normal, build and dev edges.
  3. Every one of those graphs parses completely and contains every workspace
     member and ssh-key, so an empty, truncated or substituted output cannot
     pass as "no crypto-bigint".
  4. No graph contains crypto-bigint.

Any Cargo error, unparseable line or missing check fails. The verdict is the
exit status, never the printed text.

Exit status: 0 pass, 1 crypto-bigint in the graph, 2 a cargo command failed,
3 Cargo.lock no longer matches the ignore (obsolete or changed),
4 verification incomplete (empty, unparseable or missing graph).

Usage: check_rustsec_2026_0387.py              check the repository this file is in
       check_rustsec_2026_0387.py --self-test  check the checker itself (needs
                                               cargo and crates.io access)
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

CRATE = "crypto-bigint"
LOCKED_VERSIONS = ["0.5.5"]
# The crate whose optional p256/p384/p521 dependencies are the only way in.
SENTINEL = "ssh-key"
# Linux host, the Android ABIs in .github/actions/uniffi-android-bridge
# (ABI_TARGETS), and `all`, the union over every platform cfg.
TARGETS = [
    "x86_64-unknown-linux-gnu",
    "x86_64-linux-android",
    "aarch64-linux-android",
    "all",
]
FEATURE_MODES = [[], ["--all-features"], ["--no-default-features"]]

PASS, REACHABLE, CARGO_FAILED, LOCK_CHANGED, INCOMPLETE = 0, 1, 2, 3, 4

NODE_RE = re.compile(r"(?P<name>[A-Za-z0-9_-]+) v(?P<version>[0-9][^\s]*)(?: \(.*\))?(?: \(\*\))?")
SECTION_RE = re.compile(r"\[(?:build-|dev-)?dependencies\]")


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def cargo(root, args):
    env = dict(os.environ, CARGO_TERM_COLOR="never")
    try:
        proc = subprocess.run(["cargo", *args], cwd=root, env=env, capture_output=True, text=True)
    except OSError as e:
        raise Failure(CARGO_FAILED, f"cannot run cargo: {e}")
    if proc.returncode != 0:
        raise Failure(CARGO_FAILED, f"`cargo {' '.join(args)}` exited {proc.returncode}:\n{proc.stderr.strip()}")
    return proc.stdout


def check_lock(root):
    lock = root / "Cargo.lock"
    try:
        packages = tomllib.loads(lock.read_text()).get("package", [])
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Failure(INCOMPLETE, f"cannot read {lock}: {e}")
    versions = sorted(p.get("version", "?") for p in packages if p.get("name") == CRATE)
    if not versions:
        raise Failure(LOCK_CHANGED, f"{CRATE} is no longer in Cargo.lock: remove the RUSTSEC-2026-0387 "
                                    "ignore from .cargo/audit.toml and this guard")
    if versions != LOCKED_VERSIONS:
        raise Failure(LOCK_CHANGED, f"Cargo.lock has {CRATE} {versions}, the ignore was reviewed for "
                                    f"{LOCKED_VERSIONS}: review RUSTSEC-2026-0387 again")


def workspace_members(root):
    out = cargo(root, ["metadata", "--format-version", "1", "--no-deps", "--locked"])
    try:
        names = {p["name"] for p in json.loads(out)["packages"]}
    except (ValueError, KeyError, TypeError) as e:
        raise Failure(INCOMPLETE, f"cannot parse cargo metadata: {e}")
    if not names:
        raise Failure(INCOMPLETE, "cargo metadata lists no workspace members")
    return names


def graph(root, target, features):
    args = ["tree", "--locked", "--workspace", "-e", "normal,build,dev", "--target", target,
            *features, "--prefix", "none", "--format", "{p}"]
    names = set()
    for line in cargo(root, args).splitlines():
        if not line.strip() or SECTION_RE.fullmatch(line.strip()):
            continue
        m = NODE_RE.fullmatch(line)
        if not m:
            raise Failure(INCOMPLETE, f"unparseable cargo tree line for --target {target} {features}: {line!r}")
        names.add(m["name"])
    return names


def check(root):
    """(exit status, message) for the workspace at root."""
    try:
        check_lock(root)
        members = workspace_members(root)
        done = 0
        for target in TARGETS:
            for features in FEATURE_MODES:
                names = graph(root, target, features)
                where = f"--target {target} {' '.join(features) or '(default features)'}"
                missing = sorted((members | {SENTINEL}) - names)
                if missing:
                    raise Failure(INCOMPLETE, f"graph for {where} lacks {missing}: cannot verify")
                if CRATE in names:
                    raise Failure(REACHABLE, f"{CRATE} is in the build graph for {where}: "
                                             "the RUSTSEC-2026-0387 ignore no longer holds")
                done += 1
        if done != len(TARGETS) * len(FEATURE_MODES) or done == 0:
            raise Failure(INCOMPLETE, f"ran {done} graph checks, expected {len(TARGETS) * len(FEATURE_MODES)}")
    except Failure as f:
        return f.code, str(f)
    return PASS, f"{CRATE} {LOCKED_VERSIONS} is in Cargo.lock and in none of {done} build graphs"


def copy_workspace(src, dst):
    shutil.copy2(src / "Cargo.toml", dst / "Cargo.toml")
    shutil.copy2(src / "Cargo.lock", dst / "Cargo.lock")
    shutil.copytree(src / "crates", dst / "crates", ignore=shutil.ignore_patterns("target"))
    # Path dependencies patched in from the root manifest ([patch.crates-io]).
    if (src / "vendor").is_dir():
        shutil.copytree(src / "vendor", dst / "vendor", ignore=shutil.ignore_patterns("target"))


def add_dependency(ws, dependencies, extra):
    """Add lines to core-crypto's [dependencies] and append a section."""
    manifest = ws / "crates/core-crypto/Cargo.toml"
    text = manifest.read_text()
    if text.count("\n[dependencies]\n") != 1:
        raise SystemExit("self-test fixture: expected one [dependencies] in core-crypto")
    manifest.write_text(text.replace("\n[dependencies]\n", "\n[dependencies]\n" + dependencies, 1) + extra)


def fake_cargo(directory, body):
    path = directory / "cargo"
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def self_test(root):
    results = []

    def expect(name, want, reason, ws, path_prefix=None):
        old_path = os.environ["PATH"]
        if path_prefix:
            os.environ["PATH"] = f"{path_prefix}{os.pathsep}{old_path}"
        try:
            got, message = check(ws)
        finally:
            os.environ["PATH"] = old_path
        ok = got == want and reason in message
        results.append(ok)
        print(f"{'ok  ' if ok else 'FAIL'} {name}: want {want} {reason!r}, got {got} ({message.splitlines()[0]})")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        def fixture(name):
            ws = tmp / name
            ws.mkdir()
            copy_workspace(root, ws)
            return ws

        # Current dependency graph: passes.
        expect("current graph", PASS, "in none of 12 build graphs", fixture("current"))

        # ssh-key's p256 feature turned on, Cargo.lock updated by Cargo: the
        # crate becomes reachable. Also where only one feature mode sees it
        # (behind an optional workspace feature: --all-features) and where
        # only some targets do (Android-only: the Android targets and all;
        # aarch64-only; a target not in TARGETS: only all), and through dev
        # and build edges. Features are additive, so no dependency can appear
        # under --no-default-features alone.
        dep = 'ssh-key = { version = "=0.6.7", features = ["p256"]%s }\n'
        for name, where, dependencies, extra in [
            ("ssh-key/p256 activated", "x86_64-unknown-linux-gnu (default features)", dep % "", ""),
            ("ssh-key/p256 behind a workspace feature", "x86_64-unknown-linux-gnu --all-features",
             dep % ", optional = true", '\n[features]\nrustsec-probe = ["dep:ssh-key"]\n'),
            ("ssh-key/p256 on Android only", "x86_64-linux-android (default features)", "",
             "\n[target.'cfg(target_os = \"android\")'.dependencies]\n" + dep % ""),
            ("ssh-key/p256 on aarch64 only", "aarch64-linux-android (default features)", "",
             "\n[target.'cfg(target_arch = \"aarch64\")'.dependencies]\n" + dep % ""),
            ("ssh-key/p256 on a target not listed (iOS)", "all (default features)", "",
             "\n[target.'cfg(target_os = \"ios\")'.dependencies]\n" + dep % ""),
            ("ssh-key/p256 as a dev-dependency", "x86_64-unknown-linux-gnu (default features)", "",
             "\n[dev-dependencies]\n" + dep % ""),
            ("ssh-key/p256 as a build-dependency", "x86_64-unknown-linux-gnu (default features)", "",
             "\n[build-dependencies]\n" + dep % ""),
        ]:
            ws = fixture(re.sub(r"\W+", "-", name))
            add_dependency(ws, dependencies, extra)
            subprocess.run(["cargo", "update", "--workspace", "--quiet"], cwd=ws, check=True)
            expect(name, REACHABLE, f"for --target {where}:", ws)

        # The same activation without updating Cargo.lock: --locked refuses.
        ws = fixture("stale-lock")
        add_dependency(ws, dep % "", "")
        expect("activation with a stale Cargo.lock", CARGO_FAILED, "exited 101", ws)

        # crypto-bigint gone from Cargo.lock: the ignore is obsolete.
        ws = fixture("no-crate")
        lock = ws / "Cargo.lock"
        blocks = lock.read_text().split("\n[[package]]\n")
        kept = [b for b in blocks if not b.startswith(f'name = "{CRATE}"\n')]
        if len(kept) != len(blocks) - 1:
            raise SystemExit(f"self-test fixture: expected one {CRATE} block in Cargo.lock")
        lock.write_text("\n[[package]]\n".join(kept).replace(f' "{CRATE}",\n', ""))
        expect(f"{CRATE} removed from Cargo.lock", LOCK_CHANGED, "no longer in Cargo.lock", ws)

        # crypto-bigint at a version the ignore was not reviewed for.
        ws = fixture("other-version")
        lock = ws / "Cargo.lock"
        text = lock.read_text()
        old = f'name = "{CRATE}"\nversion = "{LOCKED_VERSIONS[0]}"\n'
        if text.count(old) != 1:
            raise SystemExit(f"self-test fixture: expected one {CRATE} {LOCKED_VERSIONS[0]} entry")
        lock.write_text(text.replace(old, f'name = "{CRATE}"\nversion = "0.5.6"\n'))
        expect(f"{CRATE} at an unreviewed version", LOCK_CHANGED, "['0.5.6']", ws)

        # Fake cargo binaries: a failing command, empty output, a fabricated
        # PASS, and a plausible graph missing the workspace.
        ws = fixture("fake")
        metadata = json.dumps({"packages": [{"name": "core-transport"}]})
        for name, want, reason, body in [
            ("cargo exits non-zero", CARGO_FAILED, "exited 101", "echo 'error: simulated' >&2; exit 101"),
            ("cargo prints nothing and exits 0", INCOMPLETE, "lacks ['core-transport', 'ssh-key']",
             f"[ \"$1\" = metadata ] && echo '{metadata}'; exit 0"),
            ("cargo prints a fabricated PASS", INCOMPLETE, "unparseable",
             f"[ \"$1\" = metadata ] && echo '{metadata}' && exit 0; echo PASS; exit 0"),
            ("cargo prints a graph without the workspace", INCOMPLETE, "lacks ['core-transport']",
             f"[ \"$1\" = metadata ] && echo '{metadata}' && exit 0; echo 'ssh-key v0.6.7'; exit 0"),
        ]:
            bin_dir = tmp / f"bin-{len(results)}"
            bin_dir.mkdir()
            fake_cargo(bin_dir, body)
            expect(name, want, reason, ws, path_prefix=bin_dir)

    if len(results) != 15 or not all(results):
        print(f"self-test FAILED: {results.count(True)} of {len(results)} cases as expected, 15 required")
        return 1
    print("self-test passed: 15 of 15 cases as expected")
    return 0


def main():
    root = Path(__file__).resolve().parents[2]
    if sys.argv[1:] == ["--self-test"]:
        return self_test(root)
    if sys.argv[1:]:
        print(__doc__.split("Usage:")[1].strip(), file=sys.stderr)
        return INCOMPLETE
    code, message = check(root)
    print(f"{'::error::' if code else ''}RUSTSEC-2026-0387 guard: {message}")
    return code


if __name__ == "__main__":
    sys.exit(main())
