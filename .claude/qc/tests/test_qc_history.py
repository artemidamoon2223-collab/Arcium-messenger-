"""History integrity of .claude/qc: every run and review the signed state names must be on disk,
unchanged, signed and bound to this spec. An edited, substituted, corrupted or missing older record
must never leave the verdict VERIFIED, even when the latest run and reviews are valid.

Run with the other tests: `python3 -B -m unittest discover -s .claude/qc/tests`.
"""

import json
import os
import shutil
import tempfile
import unittest

from test_qc import FAILING, PASSING, PY, Repo, eng_pass, load, sec

CRYPTO = "crates/core-crypto/src/x.rs"
FLAKY = {"id": "ac-flag", "description": "fails while flag.fail exists; kills its runner while flag.kill exists",
         "command": [PY, "-c", "import os,signal,sys\nif os.path.exists('flag.kill'): os.kill(os.getppid(), signal.SIGKILL)\n"
                               "if os.path.exists('flag.fail'): sys.exit(1)\n"
                               "print('test result: ok. 3 passed; 0 failed')"],
         "must_match": [r"test result: ok\. [1-9][0-9]* passed; 0 failed"]}


class HistoryTest(unittest.TestCase):
    def setUp(self):
        self.parent = tempfile.mkdtemp(prefix="qc-parent-")
        self.r = Repo(parent=self.parent)

    def tearDown(self):
        shutil.rmtree(self.parent, ignore_errors=True)

    def state(self, sid):
        rc, line = self.r.qc("verdict", sid)
        return line.split("|")[0].replace("QC_STATE:", "").strip(), line

    def rec(self, sid, name):
        return os.path.join(self.r.gitdir(), "runs", sid, name)

    def verified(self, sid, files, security=True):
        self.r.review(sid, "engineering-code-review", eng_pass(self.r.base, files))
        if security:
            self.r.review(sid, "arcium-security-review", sec(self.r.base, files))
        st, line = self.state(sid)
        self.assertEqual(st, "VERIFIED", line)

    def history_failed_then_verified(self, sid):
        """run-1 FAILED, then a repair, run-2 PASS and the reviews: VERIFIED with an older FAILED run."""
        self.r.locked(sid, [FLAKY])
        self.r.write("src/app.txt", "v2\n")
        self.r.write("flag.fail", "x\n")
        self.r.qc("run", sid)
        os.remove(os.path.join(self.r.dir, "flag.fail"))
        self.r.qc("run", sid)
        self.verified(sid, ["src/app.txt"])
        runs = load(self.rec(sid, "state.json"))["runs"]
        self.assertEqual([x["outcome"] for x in runs], ["FAILED", "PASS"])

    def history_pass_then_verified(self, sid):
        """run-1 PASS on an earlier tree, run-2 PASS on the current one, reviews: VERIFIED."""
        self.r.locked(sid, [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", sid)
        self.r.write("src/app.txt", "v3\n")
        self.r.qc("run", sid)
        self.verified(sid, ["src/app.txt"])

    def kill_one_run(self, sid):
        """A run whose criterion kills qc.py before the run record is written: settled as INTERRUPTED."""
        self.r.write("flag.kill", "x\n")
        rc, _ = self.r.qc("run", sid)
        self.assertEqual(rc, -9)
        os.remove(os.path.join(self.r.dir, "flag.kill"))

    def assertBlocked(self, sid, why=None):
        st, line = self.state(sid)
        self.assertEqual(st, "BLOCKED", line)
        if why:
            self.assertIn(why, line)
        return line

    def edit(self, path, **changes):
        d = load(path)
        d.update(changes)
        with open(path, "w") as f:
            json.dump(d, f)

    # ── older runs ────────────────────────────────────────────────────────

    def test_an_edited_older_failed_run_is_blocked(self):
        self.history_failed_then_verified("t-h1")
        self.edit(self.rec("t-h1", "run-1.json"), outcome="PASS")
        self.assertBlocked("t-h1", "run-1.json")

    def test_an_edited_older_passing_run_is_blocked(self):
        self.history_pass_then_verified("t-h2")
        self.edit(self.rec("t-h2", "run-1.json"), why="edited")
        self.assertBlocked("t-h2", "run-1.json")

    def test_a_missing_older_run_is_blocked(self):
        self.history_failed_then_verified("t-h3")
        os.remove(self.rec("t-h3", "run-1.json"))
        self.assertBlocked("t-h3", "run-1.json")

    def test_a_corrupted_older_run_is_blocked(self):
        self.history_failed_then_verified("t-h4")
        with open(self.rec("t-h4", "run-1.json"), "w") as f:
            f.write('{"kind": "run", "n"')
        self.assertBlocked("t-h4", "run-1.json")

    def test_an_older_run_substituted_by_another_signed_record_is_blocked(self):
        self.history_failed_then_verified("t-h5")
        shutil.copy(self.rec("t-h5", "run-2.json"), self.rec("t-h5", "run-1.json"))
        self.assertBlocked("t-h5", "run-1.json")

    def test_a_record_appearing_for_an_interrupted_run_is_blocked(self):
        self.r.locked("t-h6", [FLAKY])
        self.r.write("src/app.txt", "v2\n")
        self.kill_one_run("t-h6")
        self.r.qc("run", "t-h6")
        self.verified("t-h6", ["src/app.txt"])
        runs = load(self.rec("t-h6", "state.json"))["runs"]
        self.assertEqual(runs[0]["outcome"], "INTERRUPTED", runs)
        shutil.copy(self.rec("t-h6", "run-2.json"), self.rec("t-h6", "run-1.json"))
        self.assertBlocked("t-h6", "run-1.json")

    # ── historical reviews ────────────────────────────────────────────────

    def test_an_edited_review_no_longer_required_is_blocked(self):
        # The security review was required for the earlier tree (a CRYPTO change); the current tree only
        # changes a document, so only the engineering review is required now and the old one is not read.
        self.r.locked("t-h7", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write(CRYPTO, "// changed\n")
        self.r.qc("run", "t-h7")
        self.verified("t-h7", [CRYPTO])
        self.r.write(CRYPTO, "// crypto\n")
        self.r.write("docs/note.md", "x\n")
        self.r.qc("run", "t-h7")
        self.verified("t-h7", ["docs/note.md"], security=False)
        reviews = load(self.rec("t-h7", "state.json"))["reviews"]
        old = [x for x in reviews if x["skill"] == "arcium-security-review"][0]
        self.edit(self.rec("t-h7", "review-%d.json" % old["n"]), blocking=[])
        self.assertBlocked("t-h7", "review-%d.json" % old["n"])

    def test_a_missing_historical_review_is_blocked(self):
        self.r.locked("t-h8", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write(CRYPTO, "// changed\n")
        self.r.qc("run", "t-h8")
        self.verified("t-h8", [CRYPTO])
        self.r.write(CRYPTO, "// crypto\n")
        self.r.write("docs/note.md", "x\n")
        self.r.qc("run", "t-h8")
        self.verified("t-h8", ["docs/note.md"], security=False)
        old = [x for x in load(self.rec("t-h8", "state.json"))["reviews"] if x["skill"] == "arcium-security-review"][0]
        os.remove(self.rec("t-h8", "review-%d.json" % old["n"]))
        self.assertBlocked("t-h8", "review-%d.json" % old["n"])

    # ── every reader of the verdict ───────────────────────────────────────

    def test_status_and_the_stop_hook_do_not_report_verified_from_a_broken_history(self):
        self.history_failed_then_verified("t-h9")
        self.r.qc("activate", "t-h9")
        os.remove(self.rec("t-h9", "run-1.json"))
        rc, out = self.r.qc("status", "t-h9")
        import subprocess
        p = subprocess.run([PY, "-B", ".claude/qc/qc.py", "status", "t-h9"], cwd=self.r.dir, capture_output=True,
                           text=True, env=self.r.env())
        self.assertEqual(json.loads(p.stdout)["verdict"]["state"], "BLOCKED", p.stdout)
        rc, out, _ = self.r.hook("stop", {"stop_hook_active": False,
                                          "last_assistant_message": "QC_STATE: VERIFIED | done"})
        self.assertEqual(json.loads(out or "{}").get("decision"), "block", out)
        rc, out, err = self.r.hook("task-completed", {"task_subject": "[qc] t"})
        self.assertEqual(rc, 2, err)

    def test_a_broken_history_also_stops_the_next_run(self):
        self.history_pass_then_verified("t-h10")
        self.edit(self.rec("t-h10", "run-1.json"), why="edited")
        rc, line = self.r.qc("run", "t-h10")
        self.assertIn("BLOCKED", line)
        self.assertEqual(len(load(self.rec("t-h10", "state.json"))["runs"]), 2, "no run is added on a broken history")

    # ── a signed ledger that disagrees with its records ───────────────────
    # These model a ledger re-signed with the clone's key (a bug, or someone with shell access): the
    # signature is valid, but the history it lists is not the history on disk.

    def resign_state(self, sid, change):
        import subprocess
        code = ("import json, sys; sys.path.insert(0, '.claude/qc'); import qc\n"
                "st = qc.load_state('.', %r)\n"
                "st.pop('hmac', None)\n"
                "%s\n"
                "qc.save_state('.', %r, st)\n") % (sid, change, sid)
        subprocess.run([PY, "-B", "-c", code], cwd=self.r.dir, check=True, env=self.r.env())

    def test_a_signed_ledger_listing_a_different_outcome_is_blocked(self):
        self.history_failed_then_verified("t-h15")
        self.resign_state("t-h15", "st['runs'][0]['outcome'] = 'PASS'; st['failed_runs'] = 0")
        self.assertBlocked("t-h15", "run-1.json does not match its ledger entry")

    def test_a_signed_ledger_with_a_wrong_failure_count_is_blocked(self):
        self.history_failed_then_verified("t-h16")
        self.resign_state("t-h16", "st['failed_runs'] = 0")
        self.assertBlocked("t-h16", "failed round")

    def test_a_record_of_another_spec_listed_in_the_ledger_is_blocked(self):
        self.history_failed_then_verified("t-h17")
        self.r.spec("t-h17b", [PASSING])  # same base: its records are signed by the same key
        self.r.write("src/app.txt", "v1\n")
        self.r.qc("lock", "t-h17b")
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-h17b")
        shutil.copy(self.rec("t-h17b", "run-1.json"), self.rec("t-h17", "run-1.json"))
        import hashlib
        with open(self.rec("t-h17", "run-1.json"), "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        self.resign_state("t-h17", "st['runs'][0].update(sha256=%r, outcome='PASS'); st['failed_runs'] = 0" % h)
        self.assertBlocked("t-h17", "run-1.json does not match its ledger entry")

    # ── what must keep working ────────────────────────────────────────────

    def test_an_intact_history_with_failed_and_interrupted_runs_still_verifies(self):
        self.r.locked("t-h11", [FLAKY])
        self.r.write("src/app.txt", "v2\n")
        self.r.write("flag.fail", "x\n")
        self.r.qc("run", "t-h11")
        os.remove(os.path.join(self.r.dir, "flag.fail"))
        self.kill_one_run("t-h11")
        self.r.qc("run", "t-h11")
        self.verified("t-h11", ["src/app.txt"])
        st = load(self.rec("t-h11", "state.json"))
        self.assertEqual([x["outcome"] for x in st["runs"]], ["FAILED", "INTERRUPTED", "PASS"])
        self.assertEqual(st["failed_runs"], 2)

    def test_a_run_recorded_just_before_a_crash_is_adopted_and_verified(self):
        self.r.locked("t-h12", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        rc, _ = self.r.qc("run", "t-h12", env={"QC_TEST_CRASH_AT": "run-recorded"})
        self.assertEqual(rc, -9)
        self.verified("t-h12", ["src/app.txt"])
        self.assertEqual([x["outcome"] for x in load(self.rec("t-h12", "state.json"))["runs"]], ["PASS"])

    def test_a_review_recorded_just_before_a_crash_is_adopted_and_verified(self):
        self.r.locked("t-h13", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-h13")
        self.r.review("t-h13", "engineering-code-review", eng_pass(self.r.base, ["src/app.txt"]))
        text = sec(self.r.base, ["src/app.txt"]).replace(
            "ARCIUM_SECURITY_REVIEW\n", "ARCIUM_SECURITY_REVIEW\nqc_fingerprint: %s\n" % self.r.fingerprint(), 1)
        rc, _ = self.r.qc("review-record", "t-h13", "arcium-security-review", stdin=text,
                          env={"QC_TEST_CRASH_AT": "review-recorded"})
        self.assertEqual(rc, -9)
        self.assertEqual(self.state("t-h13")[0], "VERIFIED")
        self.r.write("src/app.txt", "v3\n")
        self.r.qc("run", "t-h13")  # saves the adopted review into the ledger
        self.assertEqual(len(load(self.rec("t-h13", "state.json"))["reviews"]), 2)

    def test_unexpected_records_and_rollback_stay_detected(self):
        self.history_failed_then_verified("t-h14")
        shutil.copy(self.rec("t-h14", "run-2.json"), self.rec("t-h14", "run-7.json"))
        self.assertBlocked("t-h14", "run-7.json")
        os.remove(self.rec("t-h14", "run-7.json"))
        self.assertEqual(self.state("t-h14")[0], "VERIFIED")
        st = load(self.rec("t-h14", "state.json"))
        st["failed_runs"] = 0
        with open(self.rec("t-h14", "state.json"), "w") as f:
            json.dump(st, f)
        self.assertBlocked("t-h14")


if __name__ == "__main__":
    unittest.main()
