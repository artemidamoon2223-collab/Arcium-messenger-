"""Tests for .claude/qc: run with `python3 -m unittest discover -s .claude/qc/tests -v`.

Each test builds a throwaway git repository with a copy of the QC tool, so
nothing here touches the real checkout or its git directory.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

QC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(os.path.dirname(QC_DIR))
PY = sys.executable

PASSING = {"id": "ac-pass", "description": "a passing check",
           "command": [PY, "-c", "print('test result: ok. 3 passed; 0 failed')"],
           "must_match": [r"test result: ok\. [1-9][0-9]* passed; 0 failed"]}
FAILING = {"id": "ac-fail", "description": "a failing check",
           "command": [PY, "-c", "import sys; print('test result: FAILED. 1 failed'); sys.exit(101)"]}
ZERO_TESTS = {"id": "ac-zero", "description": "a filter that ran nothing",
              "command": [PY, "-c", "print('test result: ok. 0 passed; 0 failed')"],
              "must_match": [r"test result: ok\. [1-9][0-9]* passed; 0 failed"]}


def eng_pass(base, files):
    return """KARPATHY_REVIEW_RESULT
target: %s...WORKTREE
complete: yes
files: %s
think_before_coding: pass | x:1
simplicity_first: pass | x:1
surgical_changes: pass | x:1
goal_driven: pass | x:1
tests_run: none
unverified: none
summary: ok
KARPATHY_REVIEW_END""" % (base, " ".join(files))


def sec(base, files, findings="  (none)"):
    return """ARCIUM_SECURITY_REVIEW
target: %s...WORKTREE
complete: yes
coverage: %s read in full
areas: 1
findings:
%s
known_findings: none
tests_run: none
not_verified: none
verdict: x
ARCIUM_SECURITY_REVIEW_END""" % (base, ", ".join(files), findings)


HIGH = "  - HIGH | replay accepted | crates/core-crypto/src/x.rs:1 | relay replays | SOURCE_VERIFIED"


def load(path):
    with open(path) as f:
        return json.load(f)


def dump(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f)


class Repo:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="qc-test-")
        self.git("init", "-q")
        self.git("config", "user.email", "t@t")
        self.git("config", "user.name", "t")
        os.makedirs(os.path.join(self.dir, ".claude/qc"))
        for f in ("qc.py", "hooks.py"):
            shutil.copy(os.path.join(QC_DIR, f), os.path.join(self.dir, ".claude/qc", f))
        self.write("src/app.txt", "v1\n")
        self.write("crates/core-crypto/src/x.rs", "// crypto\n")
        self.write(".github/workflows/ci.yml", "jobs: {}\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *a):
        return subprocess.run(["git", "-C", self.dir, *a], capture_output=True, text=True, check=True).stdout

    def write(self, rel, text):
        p = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def env(self):
        e = dict(os.environ)
        e.pop("CLAUDE_PROJECT_DIR", None)
        return e

    def qc(self, *args, stdin=None):
        p = subprocess.run([PY, ".claude/qc/qc.py", *args], cwd=self.dir, capture_output=True, text=True,
                           input=stdin, env=self.env())
        return p.returncode, p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr

    def hook(self, event, payload, cwd=None):
        p = subprocess.run([PY, os.path.join(self.dir, ".claude/qc/hooks.py"), event], cwd=cwd or self.dir,
                           capture_output=True, text=True, input=json.dumps(payload), env=self.env())
        return p.returncode, p.stdout.strip(), p.stderr.strip()

    def spec(self, sid, criteria, **extra):
        rc, path = self.qc("spec-path", sid)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        spec = {"id": sid, "title": "t", "base": self.base, "owner_instruction": "Owner: do t",
                "owner_authorizes": [], "max_repair_rounds": 3, "criteria": criteria}
        spec.update(extra)
        with open(path, "w") as f:
            json.dump(spec, f)
        return path

    def locked(self, sid, criteria, **extra):
        self.spec(sid, criteria, **extra)
        rc, out = self.qc("lock", sid)
        assert "locked" in out, out
        return sid

    def gitdir(self):
        return os.path.join(self.dir, ".git", "arcium-qc")

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class QcTest(unittest.TestCase):
    def setUp(self):
        self.r = Repo()

    def tearDown(self):
        self.r.cleanup()

    def state(self, sid):
        rc, line = self.r.qc("verdict", sid)
        return line.split("|")[0].replace("QC_STATE:", "").strip(), line

    # ── evidence ──────────────────────────────────────────────────────────

    def test_missing_evidence_is_not_verified(self):
        self.r.locked("t-missing", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        st, line = self.state("t-missing")
        self.assertEqual(st, "NOT_VERIFIED")
        self.assertIn("no evidence", line)

    def test_markdown_pass_is_not_evidence(self):
        self.r.locked("t-md", [FAILING])
        self.r.write("QC-RESULT.md", "QC_STATE: VERIFIED\nAll criteria PASS\n")
        self.r.write("src/app.txt", "v2\n")
        st, _ = self.state("t-md")
        self.assertEqual(st, "NOT_VERIFIED")
        rc, line = self.r.qc("run", "t-md")
        self.assertIn("FAILED", line)

    def test_edited_evidence_is_rejected(self):
        self.r.locked("t-edit", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-edit")
        p = os.path.join(self.r.gitdir(), "runs/t-edit/run-1.json")
        ev = load(p)
        ev["outcome"] = "PASS"
        ev["results"][0]["status"] = "PASS"
        dump(ev, p)
        st, line = self.state("t-edit")
        self.assertEqual(st, "BLOCKED")

    def test_fabricated_run_record_is_rejected(self):
        self.r.locked("t-fab", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        d = os.path.join(self.r.gitdir(), "runs/t-fab")
        st = load(os.path.join(d, "state.json"))
        dump({"kind": "run", "outcome": "PASS", "n": 1}, os.path.join(d, "run-1.json"))
        st["runs"].append({"n": 1, "outcome": "PASS", "sha256": "0" * 64})
        dump(st, os.path.join(d, "state.json"))
        self.assertEqual(self.state("t-fab")[0], "BLOCKED")

    def test_stale_evidence_is_detected(self):
        self.r.locked("t-stale", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-stale")
        self.r.qc("review-record", "t-stale", "engineering-code-review", stdin=eng_pass(self.r.base, ["src/app.txt"]))
        self.r.qc("review-record", "t-stale", "arcium-security-review", stdin=sec(self.r.base, ["src/app.txt"]))
        self.assertEqual(self.state("t-stale")[0], "VERIFIED")
        self.r.write("src/app.txt", "v3\n")
        st, line = self.state("t-stale")
        self.assertEqual(st, "NOT_VERIFIED")
        self.assertIn("stale", line)

    def test_tree_changed_during_run_is_not_verified(self):
        writer = {"id": "ac-writes", "description": "writes a file",
                  "command": [PY, "-c", "open('src/new.txt','w').write('x')"]}
        self.r.locked("t-during", [writer])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("run", "t-during")
        self.assertIn("NOT_VERIFIED", line)

    # ── failures and budget ───────────────────────────────────────────────

    def test_failed_tests_cannot_produce_verified(self):
        self.r.locked("t-fail", [PASSING, FAILING])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("run", "t-fail")
        self.assertEqual(rc, 10)
        self.r.qc("review-record", "t-fail", "engineering-code-review", stdin=eng_pass(self.r.base, ["src/app.txt"]))
        self.assertEqual(self.state("t-fail")[0], "FAILED")

    def test_zero_tests_run_is_a_failure(self):
        self.r.locked("t-zero", [ZERO_TESTS])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("run", "t-zero")
        self.assertIn("FAILED", line)

    def test_three_repair_rounds_then_escalation(self):
        self.r.locked("t-budget", [FAILING])
        states = []
        for i in range(5):
            self.r.write("src/app.txt", "attempt %d\n" % i)
            rc, line = self.r.qc("run", "t-budget")
            states.append(line.split("|")[0].strip())
        self.assertEqual(states[:3], ["QC_STATE: FAILED"] * 3)
        self.assertEqual(states[3], "QC_STATE: ESCALATE_TO_OWNER")
        self.assertEqual(states[4], "QC_STATE: ESCALATE_TO_OWNER")
        runs = load(os.path.join(self.r.gitdir(), "runs/t-budget/state.json"))["runs"]
        self.assertEqual(len(runs), 4, "a fifth run must not execute")

    def test_resetting_the_budget_by_editing_state_is_blocked(self):
        self.r.locked("t-reset", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-reset")
        p = os.path.join(self.r.gitdir(), "runs/t-reset/state.json")
        st = load(p)
        st["failed_runs"] = 0
        dump(st, p)
        self.assertEqual(self.state("t-reset")[0], "BLOCKED")

    def test_blocking_review_counts_as_a_failed_round(self):
        self.r.locked("t-review", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write("crates/core-crypto/src/x.rs", "// changed\n")
        self.r.qc("run", "t-review")
        x = ["crates/core-crypto/src/x.rs"]
        self.r.qc("review-record", "t-review", "engineering-code-review", stdin=eng_pass(self.r.base, x))
        rc, line = self.r.qc("review-record", "t-review", "arcium-security-review", stdin=sec(self.r.base, x, HIGH))
        self.assertIn("FAILED", line)

    # ── environment ───────────────────────────────────────────────────────

    def test_missing_tool_is_not_verified(self):
        c = dict(PASSING, id="ac-tool", requires=["no-such-tool-qc"])
        c2 = {"id": "ac-notfound", "description": "x", "command": ["no-such-binary-qc", "--version"]}
        self.r.locked("t-tool", [c, c2])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("run", "t-tool")
        self.assertIn("NOT_VERIFIED", line)
        self.assertIn("no-such-tool-qc", line)

    def test_network_errors_are_not_verified(self):
        net = {"id": "ac-net", "description": "x",
               "command": [PY, "-c", "import sys; print('error: Could not resolve host: index.crates.io'); sys.exit(101)"]}
        pre = dict(PASSING, id="ac-pre", network=True, network_probe="http://127.0.0.1:9/")
        self.r.locked("t-net", [net, pre])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("run", "t-net")
        self.assertIn("NOT_VERIFIED", line)
        ev = load(os.path.join(self.r.gitdir(), "runs/t-net/run-1.json"))
        self.assertEqual([r["status"] for r in ev["results"]], ["NOT_VERIFIED", "NOT_VERIFIED"])

    def test_real_toolchain_environment_messages_are_not_verified(self):
        msgs = ["error: failed to retrieve search results from the registry at https://crates.io\nCaused by:\n"
                "  [7] Could not connect to server (Failed to connect to crates.io port 443 via 127.0.0.1)",
                "* What went wrong:\nPlugin [id: 'com.android.application', version: '8.6.1'] was not found\n"
                "- Plugin Repositories (could not resolve plugin artifact 'x')\nBUILD FAILED in 48s",
                "SDK location not found. Define a valid SDK location with an ANDROID_HOME environment variable"]
        crit = [{"id": "ac-env%d" % i, "description": "x",
                 "command": [PY, "-c", "import sys; print(%r); sys.exit(1)" % m]} for i, m in enumerate(msgs)]
        self.r.locked("t-env", crit)
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-env")
        ev = load(os.path.join(self.r.gitdir(), "runs/t-env/run-1.json"))
        self.assertEqual([r["status"] for r in ev["results"]], ["NOT_VERIFIED"] * 3)

    def test_a_failing_test_that_mentions_the_network_stays_failed(self):
        out = ("---- relay::tests::reconnect stdout ----\nError: Connection refused\n\n"
               "test result: FAILED. 12 passed; 1 failed")
        c = {"id": "ac-relay", "description": "x", "command": [PY, "-c", "import sys; print(%r); sys.exit(101)" % out]}
        self.r.locked("t-relay", [c])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("run", "t-relay")
        self.assertIn("FAILED", line)

    def test_manual_criterion_keeps_not_verified(self):
        manual = {"id": "ac-pixel", "description": "Pixel onboarding", "manual": True}
        self.r.locked("t-manual", [PASSING, manual])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("run", "t-manual")
        self.assertIn("NOT_VERIFIED", line)

    # ── spec discipline and owner gates ───────────────────────────────────

    def test_owner_only_commands_are_refused_in_criteria(self):
        for argv in (["git", "push"], ["bash", "-c", "true"], ["gh", "pr", "merge", "1"],
                     ["curl", "-X", "POST", "x"], ["anchor", "deploy"], ["env", "git", "push"]):
            sid = "t-gate-%d" % abs(hash(tuple(argv)) % 10000)
            self.r.spec(sid, [{"id": "ac-x", "description": "x", "command": argv}])
            rc, line = self.r.qc("spec-check", sid)
            self.assertIn("BLOCKED", line, argv)

    def test_a_test_run_without_proof_that_tests_ran_is_refused(self):
        for argv in (["cargo", "test", "-p", "core-crypto", "nosuchfilter"],
                     ["./gradlew", "testDebugUnitTest"], ["npx", "mocha", "src/x.test.ts"]):
            self.r.spec("t-proof", [{"id": "ac-x", "description": "x", "command": argv}])
            rc, line = self.r.qc("spec-check", "t-proof")
            self.assertIn("must_match", line, argv)
        self.r.spec("t-proof", [{"id": "ac-x", "description": "x", "command": ["cargo", "clippy", "--", "-D", "warnings"]}])
        self.assertIn("valid", self.r.qc("spec-check", "t-proof")[1])

    def test_owner_gated_diff_without_authority_escalates(self):
        self.r.locked("t-crypto", [PASSING])
        self.r.write("crates/core-crypto/src/x.rs", "// changed\n")
        rc, line = self.r.qc("run", "t-crypto")
        self.assertIn("ESCALATE_TO_OWNER", line)
        self.assertIn("CRYPTO", line)
        self.assertFalse(os.path.exists(os.path.join(self.r.gitdir(), "runs/t-crypto/run-1.json")))

    def test_authorized_owner_gated_diff_requires_security_review(self):
        self.r.locked("t-auth", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write("crates/core-crypto/src/x.rs", "// changed\n")
        self.r.qc("run", "t-auth")
        self.r.qc("review-record", "t-auth", "engineering-code-review", stdin=eng_pass(self.r.base, ["crates/core-crypto/src/x.rs"]))
        st, line = self.state("t-auth")
        self.assertEqual(st, "NOT_VERIFIED")
        self.assertIn("arcium-security-review", line)

    def test_masked_ci_gate_escalates_even_if_ci_is_authorized(self):
        self.r.locked("t-ci", [PASSING], owner_authorizes=["CI_INTEGRITY"])
        self.r.write(".github/workflows/ci.yml", "jobs: {}\n# run: cargo test || true\n")
        st, line = self.state("t-ci")
        self.assertEqual(st, "ESCALATE_TO_OWNER")

    def test_masked_gate_in_a_new_workflow_file_escalates(self):
        self.r.locked("t-ci-new", [PASSING], owner_authorizes=["CI_INTEGRITY"])
        self.r.write(".github/workflows/new.yml", "jobs:\n  t:\n    continue-on-error: true\n")
        self.assertEqual(self.state("t-ci-new")[0], "ESCALATE_TO_OWNER")

    def test_run_cap_does_not_turn_a_later_pass_into_escalation(self):
        self.r.spec("t-cap", [PASSING])
        self.r.qc("lock", "t-cap")
        self.r.write("src/app.txt", "v2\n")
        for _ in range(8):
            self.r.qc("run", "t-cap")
        self.r.qc("review-record", "t-cap", "engineering-code-review", stdin=eng_pass(self.r.base, ["src/app.txt"]))
        self.r.qc("review-record", "t-cap", "arcium-security-review", stdin=sec(self.r.base, ["src/app.txt"]))
        self.assertEqual(self.state("t-cap")[0], "VERIFIED")
        rc, line = self.r.qc("run", "t-cap")
        self.assertIn("ESCALATE_TO_OWNER", line)
        self.assertIn("run cap", line)

    def test_classify_accepts_a_spec_id(self):
        self.r.locked("t-cls", [PASSING])
        self.r.write("crates/core-crypto/src/x.rs", "// changed\n")
        p = subprocess.run([PY, ".claude/qc/qc.py", "classify", "t-cls"], cwd=self.r.dir, capture_output=True,
                           text=True, env=self.r.env())
        out = json.loads(p.stdout)
        self.assertEqual(out["base"], self.r.base)
        self.assertEqual(out["owner_gated"], ["CRYPTO"])

    def test_missing_arguments_print_usage(self):
        p = subprocess.run([PY, ".claude/qc/qc.py", "verdict"], cwd=self.r.dir, capture_output=True, text=True,
                           env=self.r.env())
        self.assertEqual(p.returncode, 2)
        self.assertIn("usage", p.stderr)

    def test_a_renamed_gated_file_is_classified_at_its_old_path(self):
        self.r.locked("t-mv", [PASSING])
        os.makedirs(os.path.join(self.r.dir, "docs"))
        self.r.git("mv", "crates/core-crypto/src/x.rs", "docs/x.md")
        st, line = self.state("t-mv")
        self.assertEqual(st, "ESCALATE_TO_OWNER")
        self.assertIn("CRYPTO", line)

    def test_unclassified_paths_require_the_security_review(self):
        self.r.locked("t-unk", [PASSING])
        self.r.write("tools/new.sh", "echo hi\n")
        self.r.qc("run", "t-unk")
        self.r.qc("review-record", "t-unk", "engineering-code-review", stdin=eng_pass(self.r.base, ["tools/new.sh"]))
        st, line = self.state("t-unk")
        self.assertEqual(st, "NOT_VERIFIED")
        self.assertIn("arcium-security-review", line)

    def test_an_added_test_ignore_escalates(self):
        self.r.locked("t-ign", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write("crates/core-crypto/src/x.rs", "#[ignore]\n#[test]\nfn t() {}\n")
        st, line = self.state("t-ign")
        self.assertEqual(st, "ESCALATE_TO_OWNER")
        self.assertIn("TEST_MASKING", line)

    def test_a_review_must_name_the_base_and_every_changed_path(self):
        self.r.locked("t-cov", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.write("src/other.txt", "new\n")
        self.r.qc("run", "t-cov")
        rc, line = self.r.qc("review-record", "t-cov", "engineering-code-review",
                             stdin=eng_pass(self.r.base, ["src/app.txt"]))
        self.assertIn("src/other.txt", line)
        rc, line = self.r.qc("review-record", "t-cov", "engineering-code-review",
                             stdin=eng_pass("0" * 40, ["src/app.txt", "src/other.txt"]))
        self.assertIn("target", line)
        st = load(os.path.join(self.r.gitdir(), "runs/t-cov/state.json"))
        self.assertEqual(st["reviews"], [], "a refused review is not recorded")

    def test_a_later_clean_review_does_not_erase_a_blocking_one(self):
        self.r.locked("t-erase", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write("crates/core-crypto/src/x.rs", "// changed\n")
        self.r.qc("run", "t-erase")
        x = ["crates/core-crypto/src/x.rs"]
        self.r.qc("review-record", "t-erase", "engineering-code-review", stdin=eng_pass(self.r.base, x))
        self.r.qc("review-record", "t-erase", "arcium-security-review", stdin=sec(self.r.base, x, HIGH))
        rc, line = self.r.qc("review-record", "t-erase", "arcium-security-review", stdin=sec(self.r.base, x))
        self.assertIn("FAILED", line)

    def test_git_read_commands_with_side_effect_flags_are_refused(self):
        for argv in (["git", "grep", "-Ocat", "x"], ["git", "diff", "--output=/tmp/x"]):
            self.r.spec("t-gitfx", [{"id": "ac-x", "description": "x", "command": argv}])
            self.assertIn("BLOCKED", self.r.qc("spec-check", "t-gitfx")[1], argv)
        self.r.spec("t-gitfx", [{"id": "ac-x", "description": "x", "command": ["git", "diff", "--check"]}])
        self.assertIn("valid", self.r.qc("spec-check", "t-gitfx")[1])

    def test_verified_names_self_declared_owner_authority(self):
        self.r.locked("t-own", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write("crates/core-crypto/src/x.rs", "// changed\n")
        self.r.qc("run", "t-own")
        x = ["crates/core-crypto/src/x.rs"]
        self.r.qc("review-record", "t-own", "engineering-code-review", stdin=eng_pass(self.r.base, x))
        self.r.qc("review-record", "t-own", "arcium-security-review", stdin=sec(self.r.base, x))
        st, line = self.state("t-own")
        self.assertEqual(st, "VERIFIED")
        self.assertIn("self-declared", line)
        self.assertIn("CRYPTO", line)

    def test_lock_requires_clean_tree_at_base(self):
        self.r.spec("t-dirty", [PASSING])
        self.r.write("src/app.txt", "implemented first\n")
        rc, line = self.r.qc("lock", "t-dirty")
        self.assertIn("BLOCKED", line)

    def test_spec_edit_after_lock_is_blocked(self):
        path = self.r.spec("t-move", [FAILING])
        self.r.qc("lock", "t-move")
        spec = load(path)
        spec["criteria"] = [PASSING]
        dump(spec, path)
        self.assertEqual(self.state("t-move")[0], "BLOCKED")

    def test_tool_edit_after_lock_is_blocked(self):
        self.r.locked("t-tool-edit", [PASSING])
        with open(os.path.join(self.r.dir, ".claude/qc/qc.py"), "a") as f:
            f.write("\n# patched\n")
        self.assertEqual(self.state("t-tool-edit")[0], "BLOCKED")

    def test_unauthorized_class_in_owner_authorizes_is_refused(self):
        self.r.spec("t-badauth", [PASSING], owner_authorizes=["EVERYTHING"])
        rc, line = self.r.qc("spec-check", "t-badauth")
        self.assertIn("BLOCKED", line)

    # ── hooks ─────────────────────────────────────────────────────────────

    def test_hooks_do_nothing_without_an_active_loop(self):
        self.r.locked("t-idle", [FAILING])
        for ev, payload in (("stop", {"last_assistant_message": "QC_STATE: VERIFIED"}),
                            ("task-completed", {"task_subject": "[qc] x"}),
                            ("pre-tool", {"tool_name": "Bash", "tool_input": {"command": "git push"}})):
            self.assertEqual(self.r.hook(ev, payload), (0, "", ""), ev)
        self.assertFalse(os.path.exists(os.path.join(self.r.gitdir(), "active.json")))

    def test_hooks_do_nothing_outside_a_git_repo(self):
        elsewhere = tempfile.mkdtemp()
        try:
            for ev in ("stop", "task-completed", "pre-tool"):
                rc, out, err = self.r.hook(ev, {"cwd": elsewhere, "tool_name": "Bash",
                                                "tool_input": {"command": "git push"}}, cwd=elsewhere)
                self.assertEqual((rc, out), (0, ""), ev)
        finally:
            shutil.rmtree(elsewhere)

    def test_hooks_fail_open_on_garbage_input(self):
        p = subprocess.run([PY, os.path.join(self.r.dir, ".claude/qc/hooks.py"), "stop"], cwd=self.r.dir,
                           capture_output=True, text=True, input="{not json", env=self.r.env())
        self.assertEqual((p.returncode, p.stdout), (0, ""))

    def test_stop_hook_blocks_a_false_verified_claim_once(self):
        self.r.locked("t-stop", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-stop")
        self.r.qc("activate", "t-stop")
        rc, out, _ = self.r.hook("stop", {"stop_hook_active": False,
                                          "last_assistant_message": "Done.\nQC_STATE: VERIFIED | all good"})
        self.assertEqual(json.loads(out)["decision"], "block")
        self.assertIn("FAILED", json.loads(out)["reason"])
        rc, out, _ = self.r.hook("stop", {"stop_hook_active": True,
                                          "last_assistant_message": "QC_STATE: VERIFIED"})
        self.assertEqual(rc, 0)
        self.assertNotIn("decision", json.loads(out), "stop_hook_active must never block again")
        self.assertIn("QC WARNING", json.loads(out)["systemMessage"])
        rc, out, _ = self.r.hook("stop", {"stop_hook_active": False,
                                          "last_assistant_message": "QC_STATE: FAILED | ac-fail"})
        self.assertEqual(out, "")

    def test_stop_hook_allows_a_true_verified_claim(self):
        self.r.locked("t-true", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-true")
        self.r.qc("review-record", "t-true", "engineering-code-review", stdin=eng_pass(self.r.base, ["src/app.txt"]))
        self.r.qc("review-record", "t-true", "arcium-security-review", stdin=sec(self.r.base, ["src/app.txt"]))
        self.r.qc("activate", "t-true")
        rc, out, _ = self.r.hook("stop", {"last_assistant_message": "QC_STATE: VERIFIED | run 1"})
        self.assertEqual((rc, out), (0, ""))

    def test_stop_hook_enforces_escalation(self):
        self.r.locked("t-esc", [FAILING])
        for i in range(4):
            self.r.write("src/app.txt", "a%d\n" % i)
            self.r.qc("run", "t-esc")
        self.r.qc("activate", "t-esc")
        rc, out, _ = self.r.hook("stop", {"last_assistant_message": "Trying again.\nQC_STATE: FAILED"})
        self.assertEqual(json.loads(out)["decision"], "block")
        rc, out, _ = self.r.hook("stop", {"last_assistant_message": "QC_STATE: ESCALATE_TO_OWNER | budget"})
        self.assertEqual(out, "")

    def test_task_completed_hook(self):
        self.r.locked("t-task", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-task")
        self.r.qc("activate", "t-task")
        rc, out, err = self.r.hook("task-completed", {"task_subject": "[qc] implement fix"})
        self.assertEqual(rc, 2)
        self.assertIn("FAILED", err)
        self.assertEqual(self.r.hook("task-completed", {"task_subject": "unrelated chore"})[0], 0)

    def test_owner_only_operations_are_denied_and_nothing_is_allowed(self):
        self.r.locked("t-pre", [PASSING])
        self.r.qc("activate", "t-pre")
        denied = [
            {"tool_name": "Bash", "tool_input": {"command": "git push -u origin main"}},
            {"tool_name": "Bash", "tool_input": {"command": "cd x && git -C /r commit -m y"}},
            {"tool_name": "Bash", "tool_input": {"command": "git merge feature"}},
            {"tool_name": "Bash", "tool_input": {"command": "/usr/bin/git push origin x"}},
            {"tool_name": "Bash", "tool_input": {"command": "\\git push"}},
            {"tool_name": "Bash", "tool_input": {"command": "\"git\" push"}},
            {"tool_name": "Bash", "tool_input": {"command": "GIT_DIR=.git git -c a=b tag v1"}},
            {"tool_name": "Bash", "tool_input": {"command": "rm .git/arcium-qc/active.json"}},
            {"tool_name": "Bash", "tool_input": {"command": "git --git-dir=.git --work-tree=. push"}},
            {"tool_name": "Write", "tool_input": {"file_path": os.path.join(self.r.dir, ".git/arcium-qc/runs/t-pre/run-1.json")}},
            {"tool_name": "Edit", "tool_input": {"file_path": os.path.join(self.r.dir, ".git/config")}},
            {"tool_name": "Bash", "tool_input": {"command": "git checkout -- .claude/qc/qc.py"}},
            {"tool_name": "Bash", "tool_input": {"command": "gh pr merge 5"}},
            {"tool_name": "Bash", "tool_input": {"command": "gh workflow run android-ci.yml"}},
            {"tool_name": "Bash", "tool_input": {"command": "anchor deploy"}},
            {"tool_name": "Bash", "tool_input": {"command": "sed -i s/a/b/ .claude/qc/qc.py"}},
            {"tool_name": "Bash", "tool_input": {"command": "echo x > .claude/settings.json"}},
            {"tool_name": "Bash", "tool_input": {"command": "python3 -c \"open('.claude/qc/qc.py','w')\""}},
            {"tool_name": "mcp__github__merge_pull_request", "tool_input": {}},
            {"tool_name": "mcp__github__actions_run_trigger", "tool_input": {}},
            {"tool_name": "mcp__github__push_files", "tool_input": {}},
            {"tool_name": "Edit", "tool_input": {"file_path": os.path.join(self.r.dir, ".claude/qc/qc.py")}},
            {"tool_name": "Write", "tool_input": {"file_path": os.path.join(self.r.dir, "CLAUDE.md")}},
            {"tool_name": "Edit", "tool_input": {"file_path": os.path.join(self.r.dir, ".claude/settings.local.json")}},
        ]
        silent = [
            {"tool_name": "Bash", "tool_input": {"command": "git status && git diff"}},
            {"tool_name": "Bash", "tool_input": {"command": "git merge-base --is-ancestor a b"}},
            {"tool_name": "Bash", "tool_input": {"command": "git tag -l"}},
            {"tool_name": "Bash", "tool_input": {"command": "gh pr view 5"}},
            {"tool_name": "Bash", "tool_input": {"command": "cargo test -p core-crypto"}},
            {"tool_name": "Bash", "tool_input": {"command": "python3 .claude/qc/qc.py run t-pre 2>&1"}},
            {"tool_name": "mcp__github__pull_request_read", "tool_input": {}},
            {"tool_name": "Edit", "tool_input": {"file_path": os.path.join(self.r.dir, "src/app.txt")}},
        ]
        for p in denied:
            rc, out, _ = self.r.hook("pre-tool", p)
            self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny", p)
        for p in silent:
            self.assertEqual(self.r.hook("pre-tool", p), (0, "", ""), p)

    def test_hooks_leave_the_working_tree_untouched(self):
        self.r.locked("t-clean", [PASSING])
        self.r.qc("activate", "t-clean")
        before = self.r.git("status", "--porcelain", "--untracked-files=all")
        self.r.hook("stop", {"last_assistant_message": "x"})
        self.r.hook("pre-tool", {"tool_name": "Bash", "tool_input": {"command": "ls"}})
        self.assertEqual(self.r.git("status", "--porcelain", "--untracked-files=all"), before)

    def test_a_loop_cannot_be_switched_off_mid_repair(self):
        self.r.locked("t-off", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-off")
        self.r.qc("activate", "t-off")
        rc, line = self.r.qc("deactivate")
        self.assertIn("FAILED", line)
        self.assertTrue(os.path.exists(os.path.join(self.r.gitdir(), "active.json")))

    def test_evidence_command_shows_failure_tails(self):
        self.r.locked("t-ev", [PASSING, FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-ev")
        p = subprocess.run([PY, ".claude/qc/qc.py", "evidence", "t-ev"], cwd=self.r.dir, capture_output=True,
                           text=True, env=self.r.env())
        self.assertIn("ac-fail", p.stdout)
        self.assertIn("test result: FAILED", p.stdout)
        self.assertIn("run 1: FAILED", p.stdout)

    def test_expired_activation_is_ignored(self):
        self.r.locked("t-exp", [PASSING])
        self.r.qc("activate", "t-exp")
        # Re-sign an already expired activation with the clone's own key.
        sys.path.insert(0, os.path.join(self.r.dir, ".claude/qc"))
        try:
            import importlib
            import qc as qcmod
            importlib.reload(qcmod)
            qcmod.write_json(os.path.join(self.r.gitdir(), "active.json"),
                             qcmod.sign(self.r.dir, {"spec_id": "t-exp", "expires": int(time.time()) - 1}))
        finally:
            sys.path.pop(0)
        rc, out, _ = self.r.hook("pre-tool", {"tool_name": "Bash", "tool_input": {"command": "git push"}})
        self.assertEqual(out, "")


class StaticTest(unittest.TestCase):
    """Properties of the shipped files themselves."""

    def read(self, rel):
        with open(os.path.join(REPO, rel)) as f:
            return f.read()

    def test_no_skill_or_agent_grants_permissions(self):
        for d in (".claude/skills", ".claude/agents"):
            for root, _, files in os.walk(os.path.join(REPO, d)):
                for f in files:
                    with open(os.path.join(root, f)) as fh:
                        text = fh.read()
                    head = text.split("---", 2)[1] if text.startswith("---") else ""
                    for bad in ("allowed-tools", "permissionMode", "bypassPermissions", "hooks:"):
                        self.assertNotIn(bad, head, "%s/%s" % (root, f))

    def test_hooks_never_emit_allow(self):
        src = self.read(".claude/qc/hooks.py")
        self.assertNotIn('"allow"', src)
        self.assertNotIn("'allow'", src)

    def test_candidate_hooks_are_not_enabled_by_default(self):
        text = self.read(".claude/settings.json")
        self.assertNotIn("qc/hooks.py", text)
        self.assertIn("continuity.sh", text)

    def test_classification_rules_point_at_existing_paths(self):
        p = subprocess.run([PY, os.path.join(REPO, ".claude/qc/qc.py"), "self-test"], cwd=REPO,
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout)


if __name__ == "__main__":
    unittest.main()
