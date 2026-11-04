"""Second-round adversarial tests for .claude/qc: corrupt state, interrupted and
concurrent runs, reviews bound to the verified tree, the run cap in the verdict,
escalation without a claim, and the status command.

Run with the other tests: `python3 -B -m unittest discover -s .claude/qc/tests`.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from test_qc import FAILING, PASSING, PY, Repo, eng_pass, load, sec

FILES = ["src/app.txt"]


class HardeningTest(unittest.TestCase):
    def setUp(self):
        self.r = Repo()
        self.tmp = tempfile.mkdtemp(prefix="qc-flags-")

    def tearDown(self):
        self.r.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def state(self, sid):
        rc, line = self.r.qc("verdict", sid)
        return line.split("|")[0].replace("QC_STATE:", "").strip(), line

    def flag(self, name):
        return os.path.join(self.tmp, name)

    # ── corrupt state ─────────────────────────────────────────────────────

    def test_a_corrupt_state_is_blocked_and_the_stop_hook_still_holds(self):
        self.r.locked("t-corrupt", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-corrupt")
        self.r.qc("activate", "t-corrupt")
        with open(os.path.join(self.r.gitdir(), "runs/t-corrupt/state.json"), "w") as f:
            f.write('{"runs": [')  # a write cut short
        rc, line = self.r.qc("verdict", "t-corrupt")
        self.assertEqual(rc, 12, line)
        self.assertTrue(line.startswith("QC_STATE: BLOCKED"), line)
        rc, out, _ = self.r.hook("stop", {"stop_hook_active": False,
                                          "last_assistant_message": "QC_STATE: VERIFIED | done"})
        self.assertEqual(json.loads(out or "{}").get("decision"), "block",
                         "a crash in the verdict must not let a false VERIFIED through")

    # ── interrupted and concurrent runs ───────────────────────────────────

    def test_an_interrupted_run_leaves_no_verified_and_is_counted(self):
        kill = self.flag("kill")
        crit = {"id": "ac-pass", "description": "passes unless told to kill its runner",
                "command": [PY, "-c", "import os,signal\nif os.path.exists(%r): os.kill(os.getppid(), signal.SIGKILL)\n"
                                      "print('test result: ok. 3 passed; 0 failed')" % kill],
                "must_match": [r"test result: ok\. [1-9][0-9]* passed; 0 failed"]}
        self.r.locked("t-intr", [crit])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-intr")
        self.r.review("t-intr", "engineering-code-review", eng_pass(self.r.base, FILES))
        self.r.review("t-intr", "arcium-security-review", sec(self.r.base, FILES))
        self.assertEqual(self.state("t-intr")[0], "VERIFIED")
        open(kill, "w").close()
        rc, _ = self.r.qc("run", "t-intr")
        self.assertEqual(rc, -9, "the runner was killed mid-run")
        st, line = self.state("t-intr")
        self.assertEqual(st, "NOT_VERIFIED", line)
        self.assertIn("interrupted", line)
        os.remove(kill)
        self.r.qc("run", "t-intr")
        runs = load(os.path.join(self.r.gitdir(), "runs/t-intr/state.json"))["runs"]
        self.assertEqual([x["outcome"] for x in runs], ["PASS", "INTERRUPTED", "PASS"])
        self.assertEqual(self.state("t-intr")[0], "VERIFIED")

    def test_a_second_run_while_one_is_running_is_refused(self):
        started, release = self.flag("started"), self.flag("release")
        crit = {"id": "ac-wait", "description": "waits for the test to release it",
                "command": [PY, "-c", "import os,time\nopen(%r,'w').close()\n"
                                      "t=time.time()\nwhile not os.path.exists(%r) and time.time()-t<30: time.sleep(0.1)\n"
                                      "print('ok')" % (started, release)]}
        self.r.locked("t-conc", [crit])
        self.r.write("src/app.txt", "v2\n")
        first = subprocess.Popen([PY, ".claude/qc/qc.py", "run", "t-conc"], cwd=self.r.dir, env=self.r.env(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            t = time.time()
            while not os.path.exists(started) and time.time() - t < 20:
                time.sleep(0.05)
            self.assertTrue(os.path.exists(started))
            try:
                second = subprocess.run([PY, ".claude/qc/qc.py", "run", "t-conc"], cwd=self.r.dir,
                                        env=self.r.env(), capture_output=True, text=True, timeout=10)
                out = second.stdout
            except subprocess.TimeoutExpired:
                out = "a second run started its own criteria instead of refusing"
            self.assertIn("in progress", out)
            st, line = self.state("t-conc")
            self.assertEqual(st, "NOT_VERIFIED")
            self.assertIn("in progress", line)
        finally:
            open(release, "w").close()
            first.communicate(timeout=60)
        runs = load(os.path.join(self.r.gitdir(), "runs/t-conc/state.json"))["runs"]
        self.assertEqual(len(runs), 1)

    # ── reviews are bound to the tree that passed ─────────────────────────

    def test_a_review_must_quote_the_tree_its_run_passed(self):
        self.r.locked("t-bind", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("review-record", "t-bind", "engineering-code-review",
                             stdin=eng_pass(self.r.base, FILES))
        self.assertIn("NOT_VERIFIED", line, "a review without a fingerprint, before any run")
        self.r.qc("run", "t-bind")
        fp_old = self.r.fingerprint()
        self.r.write("src/app.txt", "v3\n")  # changed after the run, before the review
        rc, line = self.r.review("t-bind", "engineering-code-review", eng_pass(self.r.base, FILES))
        self.assertIn("NOT_VERIFIED", line, "no passing run on this tree yet")
        rc, line = self.r.review("t-bind", "arcium-security-review", sec(self.r.base, FILES), fp=fp_old)
        self.assertIn("NOT_VERIFIED", line, "the review quotes another tree")
        self.r.qc("run", "t-bind")
        st, line = self.state("t-bind")
        self.assertEqual(st, "NOT_VERIFIED", line)
        self.assertIn("review pending", line)

    # ── budget ────────────────────────────────────────────────────────────

    def test_the_run_cap_without_a_pass_escalates_in_the_verdict(self):
        c = dict(PASSING, id="ac-tool", requires=["no-such-tool-qc"])
        self.r.locked("t-capnv", [c])
        self.r.write("src/app.txt", "v2\n")
        for _ in range(8):
            self.r.qc("run", "t-capnv")
        st, line = self.state("t-capnv")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)

    def test_the_stop_hook_surfaces_escalation_without_any_claim(self):
        self.r.locked("t-esc2", [FAILING])
        for i in range(4):
            self.r.write("src/app.txt", "a%d\n" % i)
            self.r.qc("run", "t-esc2")
        self.r.qc("activate", "t-esc2")
        rc, out, _ = self.r.hook("stop", {"last_assistant_message": "Let me try a different approach."})
        self.assertEqual(json.loads(out or "{}").get("decision"), "block")

    # ── spec ──────────────────────────────────────────────────────────────

    def test_a_test_run_that_expects_failure_is_refused(self):
        c = {"id": "ac-neg", "description": "tests 'pass' when they fail",
             "command": ["cargo", "test", "--workspace"], "must_match": ["test result"], "expect_exit": 101}
        self.r.spec("t-neg", [c])
        rc, line = self.r.qc("spec-check", "t-neg")
        self.assertIn("BLOCKED", line)
        self.assertIn("expect_exit", line)

    # ── progress ──────────────────────────────────────────────────────────

    def test_status_shows_progress_for_the_owner(self):
        self.r.locked("t-status", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-status")
        p = subprocess.run([PY, ".claude/qc/qc.py", "status", "t-status"], cwd=self.r.dir, capture_output=True,
                           text=True, env=self.r.env())
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        s = json.loads(p.stdout)
        self.assertEqual([x["outcome"] for x in s["runs"]], ["FAILED"])
        self.assertEqual(s["repair_rounds_left"], 3)
        self.assertEqual(s["runs_left"], 7)
        self.assertEqual(s["verdict"]["state"], "FAILED")
        self.assertEqual(s["fingerprint"], self.r.fingerprint())
        self.assertEqual(s["base"], self.r.base)


if __name__ == "__main__":
    unittest.main()
