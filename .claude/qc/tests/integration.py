#!/usr/bin/env python3
"""Real-toolchain integration checks for .claude/qc. Local and opt-in: the
file name keeps it out of `unittest discover`, and it is not run in CI.

    python3 -B .claude/qc/tests/integration.py            # cargo scenarios
    QC_INTEGRATION_GRADLE=1 python3 -B .claude/qc/tests/integration.py

Needs git and cargo (and, for the Gradle observation, java and network
access to services.gradle.org). It clones this checkout's HEAD into a
temporary directory and drives qc.py there with real `cargo` runs. A QC tool
committed at HEAD is used as committed (uncommitted edits to it are not
tested; commit them first); one not yet committed is copied from this
checkout, hidden from the diff through .git/info/exclude. It writes nothing
to this checkout. Set
QC_INTEGRATION_TARGET to reuse a Cargo target directory between runs.

Exits non-zero at the first unmet expectation.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
OK_RE = r"test result: ok\. [1-9][0-9]* passed; 0 failed"
PROBE = "crates/core-crypto/tests/qc_probe.rs"
FAILING = "#[test]\nfn qc_probe() {\n    assert_eq!(1 + 1, 3, \"deliberate failure\");\n}\n"
FIXED = "#[test]\nfn qc_probe() {\n    assert_eq!(1 + 1, 2);\n}\n"
OWNER = "Integration fixture for the QC tool; not an Owner instruction."


def install_untracked(clone, files, exclude):
    """Copy QC files the clone's HEAD lacks; keep the committed ones as they are."""
    if subprocess.run(["git", "-C", clone, "ls-files", "--error-unmatch", files[0]],
                      capture_output=True).returncode == 0:
        dirty = subprocess.run(["git", "-C", SRC, "status", "--porcelain", "--", *files],
                               capture_output=True, text=True).stdout.strip()
        if dirty:
            print("WARNING: uncommitted QC changes in %s are not tested:\n%s" % (SRC, dirty))
        return
    for rel in files:
        os.makedirs(os.path.dirname(os.path.join(clone, rel)), exist_ok=True)
        shutil.copy(os.path.join(SRC, rel), os.path.join(clone, rel))
    with open(os.path.join(clone, ".git/info/exclude"), "a") as f:
        f.write("\n" + "\n".join(exclude) + "\n")


class Clone:
    def __init__(self, tmp):
        self.dir = os.path.join(tmp, "repo")
        subprocess.run(["git", "clone", "-q", "--no-hardlinks", SRC, self.dir], check=True)
        os.makedirs(os.path.join(self.dir, ".claude/qc"), exist_ok=True)
        install_untracked(self.dir, [".claude/qc/qc.py", ".claude/qc/hooks.py"], [".claude/qc/"])
        target = os.environ.get("QC_INTEGRATION_TARGET") or os.path.join(tmp, "target")
        self.env = dict(os.environ, CARGO_TARGET_DIR=target, PYTHONDONTWRITEBYTECODE="1")
        self.env.pop("CLAUDE_PROJECT_DIR", None)
        self.base = self.git("rev-parse", "HEAD")
        assert self.git("status", "--porcelain", "--untracked-files=all") == "", "clone is not clean"

    def git(self, *a):
        return subprocess.run(["git", "-C", self.dir, *a], capture_output=True, text=True,
                              check=True).stdout.strip()

    def qc(self, *a, stdin=None):
        p = subprocess.run([sys.executable, "-B", ".claude/qc/qc.py", *a], cwd=self.dir, env=self.env,
                           capture_output=True, text=True, input=stdin)
        lines = p.stdout.strip().splitlines()
        line = lines[-1] if lines else p.stderr.strip()
        print("  qc.py %s -> rc=%d %s" % (" ".join(a), p.returncode, line[:200]), flush=True)
        return p.returncode, line

    def spec(self, sid, criteria, **extra):
        _, path = self.qc("spec-path", sid)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        s = {"id": sid, "title": sid, "base": self.base, "owner_instruction": OWNER,
             "owner_authorizes": [], "max_repair_rounds": 3, "criteria": criteria}
        s.update(extra)
        with open(path, "w") as f:
            json.dump(s, f, indent=1)

    def write(self, rel, text):
        p = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def remove(self, rel):
        os.remove(os.path.join(self.dir, rel))

    def status(self, sid):
        p = subprocess.run([sys.executable, "-B", ".claude/qc/qc.py", "status", sid], cwd=self.dir, env=self.env,
                           capture_output=True, text=True, check=True)
        return json.loads(p.stdout)

    def evidence(self, sid, n):
        _, path = self.qc("spec-path", sid)
        with open(os.path.join(os.path.dirname(os.path.dirname(path)), "runs", sid, "run-%d.json" % n)) as f:
            return json.load(f)


def expect(cond, what):
    if not cond:
        print("UNMET: " + what)
        sys.exit(1)
    print("  ok: " + what)


def state(line):
    return line.split("|")[0].replace("QC_STATE:", "").strip()


def review_blocks(base, path, fp):
    eng = ("KARPATHY_REVIEW_RESULT\nqc_fingerprint: %s\ntarget: %s...WORKTREE\ncomplete: yes\nfiles: %s\n"
           "think_before_coding: pass | fixture\nsimplicity_first: pass | fixture\n"
           "surgical_changes: pass | fixture\ngoal_driven: pass | fixture\ntests_run: none\n"
           "unverified: fixture, not a review\nsummary: fixture\nKARPATHY_REVIEW_END" % (fp, base, path))
    sec = ("ARCIUM_SECURITY_REVIEW\nqc_fingerprint: %s\ntarget: %s...WORKTREE\ncomplete: yes\ncoverage: %s read in full\n"
           "areas: fixture\nfindings:\n  (none)\nknown_findings: none\ntests_run: none\n"
           "not_verified: fixture, not a review\nverdict: fixture\nARCIUM_SECURITY_REVIEW_END" % (fp, base, path))
    return eng, sec


def cargo_criteria():
    return [
        {"id": "ac-probe", "description": "regression probe passes", "requires": ["cargo"], "timeout": 1800,
         "command": ["cargo", "test", "--locked", "-p", "core-crypto", "--test", "qc_probe"],
         "must_match": [OK_RE]},
        {"id": "ac-ratchet", "description": "ratchet unit tests still pass", "requires": ["cargo"],
         "timeout": 1800, "command": ["cargo", "test", "--locked", "-p", "core-crypto", "--lib", "ratchet"],
         "must_match": [OK_RE]},
        {"id": "ac-clippy", "description": "clippy clean on core-crypto incl. tests", "requires": ["cargo"],
         "timeout": 1800,
         "command": ["cargo", "clippy", "--locked", "-p", "core-crypto", "--all-targets", "--", "-D", "warnings"]},
    ]


def scenario_repair_to_verified(c):
    print("A: real failure -> repair -> reviews -> VERIFIED -> stale")
    c.spec("int-a", cargo_criteria(), owner_authorizes=["CRYPTO"])
    expect(state(c.qc("lock", "int-a")[1]) == "NOT_VERIFIED", "lock")
    expect("no evidence" in c.qc("verdict", "int-a")[1], "missing evidence is NOT_VERIFIED")
    c.write(PROBE, FAILING)
    expect(state(c.qc("run", "int-a")[1]) == "FAILED", "a failing cargo test is FAILED")
    r = {x["id"]: x for x in c.evidence("int-a", 1)["results"]}
    expect(r["ac-probe"]["status"] == "FAIL" and r["ac-probe"]["exit_code"] == 101, "cargo exit 101 recorded")
    c.write(PROBE, FIXED)
    expect("stale" in c.qc("verdict", "int-a")[1], "evidence for the old tree is stale")
    expect("review pending" in c.qc("run", "int-a")[1], "passing criteria wait for the reviews")
    eng, sec = review_blocks(c.base, PROBE, c.status("int-a")["fingerprint"])
    c.qc("review-record", "int-a", "engineering-code-review", stdin=eng)
    line = c.qc("review-record", "int-a", "arcium-security-review", stdin=sec)[1]
    expect(state(line) == "VERIFIED" and "self-declared" in line, "VERIFIED, naming the self-declared CRYPTO")
    c.write(PROBE, FIXED + "// touched after verification\n")
    expect("stale" in c.qc("verdict", "int-a")[1], "a change after VERIFIED makes it stale")
    c.remove(PROBE)


def scenario_budget(c):
    print("B: persistent real failure -> ESCALATE_TO_OWNER after three repair rounds")
    c.spec("int-b", cargo_criteria()[:1], owner_authorizes=["CRYPTO"])
    c.qc("lock", "int-b")
    states = []
    for i in range(5):
        c.write(PROBE, FAILING.replace("deliberate failure", "attempt %d" % i))
        states.append(state(c.qc("run", "int-b")[1]))
    expect(states == ["FAILED"] * 3 + ["ESCALATE_TO_OWNER"] * 2, "FAILED x3, then ESCALATE_TO_OWNER")
    _, path = c.qc("spec-path", "int-b")
    runs = [f for f in os.listdir(os.path.join(os.path.dirname(os.path.dirname(path)), "runs", "int-b"))
            if f.startswith("run-")]
    expect(len(runs) == 4, "the fifth run did not execute")
    c.remove(PROBE)


def scenario_environment(c):
    print("C: missing tools, paths, variables and network are NOT_VERIFIED, never FAILED")
    crit = [
        {"id": "ac-tool", "description": "missing tool", "command": ["cargo", "--version"],
         "requires": ["qc-no-such-tool"]},
        {"id": "ac-path", "description": "missing path", "command": ["cargo", "--version"],
         "requires_path": ["arcium-psi/tests/qc-no-such-dir"]},
        {"id": "ac-env", "description": "missing SDK variable", "command": ["cargo", "--version"],
         "requires_env_any": ["QC_NO_SUCH_SDK_ROOT"]},
        {"id": "ac-net-preflight", "description": "network preflight to a closed port",
         "command": ["cargo", "--version"], "network": True, "network_probe": "http://127.0.0.1:9/"},
        {"id": "ac-net-real", "description": "crates.io through a dead proxy",
         "command": ["cargo", "search", "arcium", "--limit", "1"], "timeout": 120,
         "env": {"HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
                 "CARGO_NET_OFFLINE": "false"}},
    ]
    if os.environ.get("QC_INTEGRATION_GRADLE") == "1" and \
            not (os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")):
        crit.append({"id": "ac-gradle", "description": "Kotlin unit tests without an Android SDK",
                     "command": ["./gradlew", "testDebugUnitTest", "--no-daemon", "--console=plain"],
                     "cwd": "android", "timeout": 900, "must_match": ["^> Task :app:testDebugUnitTest$"]})
    c.spec("int-c", crit)
    c.qc("lock", "int-c")
    expect(state(c.qc("run", "int-c")[1]) == "NOT_VERIFIED", "the run is NOT_VERIFIED")
    for r in c.evidence("int-c", 1)["results"]:
        print("    %-17s %-12s %s" % (r["id"], r["status"], r.get("reason", "")[:110]))
        expect(r["status"] == "NOT_VERIFIED", "%s is NOT_VERIFIED" % r["id"])


def scenario_owner_gate(c):
    print("D: a crypto diff without Owner authority escalates before anything runs")
    c.spec("int-d", cargo_criteria()[1:2])
    c.qc("lock", "int-d")
    c.write("crates/core-crypto/src/qc_note.rs", "// not authorized\n")
    line = c.qc("run", "int-d")[1]
    expect(state(line) == "ESCALATE_TO_OWNER" and "CRYPTO" in line, "ESCALATE_TO_OWNER naming CRYPTO")
    _, path = c.qc("spec-path", "int-d")
    expect(not os.path.exists(os.path.join(os.path.dirname(os.path.dirname(path)), "runs", "int-d",
                                           "run-1.json")), "no criterion ran")
    c.remove("crates/core-crypto/src/qc_note.rs")


def scenario_interrupted(c):
    print("E: qc.py killed in the middle of a real cargo run -> NOT_VERIFIED, counted, then recovers")
    c.spec("int-e", cargo_criteria()[:1], owner_authorizes=["CRYPTO"])
    c.qc("lock", "int-e")
    c.write(PROBE, FIXED)
    env = dict(c.env, CARGO_TARGET_DIR=c.env["CARGO_TARGET_DIR"] + "-int-e")  # a cold build: time to kill it
    p = subprocess.Popen([sys.executable, "-B", ".claude/qc/qc.py", "run", "int-e"], cwd=c.dir, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.time() + 120
    while time.time() < deadline and not c.status("int-e")["inflight"]:
        time.sleep(0.2)
    expect(c.status("int-e")["inflight"] is not None, "the run is recorded as in flight")
    expect("in progress" in c.qc("verdict", "int-e")[1], "while it runs, the verdict says so")
    expect("in progress" in c.qc("run", "int-e")[1], "a second run is refused")
    time.sleep(2)
    os.killpg(p.pid, signal.SIGKILL)
    p.wait()
    line = c.qc("verdict", "int-e")[1]
    expect(state(line) == "NOT_VERIFIED" and "interrupted" in line, "a killed run is NOT_VERIFIED (interrupted)")
    expect("review pending" in c.qc("run", "int-e")[1], "the next run completes")
    expect([r["outcome"] for r in c.status("int-e")["runs"]] == ["INTERRUPTED", "PASS"],
           "the interrupted run stays in the ledger")
    c.remove(PROBE)


def main():
    if shutil.which("cargo") is None:
        print("NOT_VERIFIED: cargo is not installed")
        return 2
    with tempfile.TemporaryDirectory(prefix="qc-integration-") as tmp:
        c = Clone(tmp)
        print("clone of %s at %s" % (SRC, c.base))
        scenario_environment(c)
        scenario_repair_to_verified(c)
        scenario_budget(c)
        scenario_owner_gate(c)
        scenario_interrupted(c)
        expect(c.git("status", "--porcelain", "--untracked-files=all") == "", "the clone is clean again")
    print("ALL INTEGRATION EXPECTATIONS MET")
    return 0


if __name__ == "__main__":
    sys.exit(main())
