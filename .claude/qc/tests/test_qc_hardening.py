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

from test_qc import FAILING, HIGH, PASSING, PY, Repo, eng_pass, load, sec

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


WF = ".github/workflows/ci.yml"
CRYPTO = "crates/core-crypto/src/x.rs"


class ReviewFindingsTest(unittest.TestCase):
    """Defects an independent review found in 2f3c37b; each test fails there."""

    def setUp(self):
        self.parent = tempfile.mkdtemp(prefix="qc-parent-")
        self.r = Repo(parent=self.parent)

    def tearDown(self):
        shutil.rmtree(self.parent, ignore_errors=True)

    def state(self, sid):
        rc, line = self.r.qc("verdict", sid)
        return line.split("|")[0].replace("QC_STATE:", "").strip(), line

    def verified(self, sid, files):
        self.r.qc("run", sid)
        self.r.review(sid, "engineering-code-review", eng_pass(self.r.base, files))
        return self.r.review(sid, "arcium-security-review", sec(self.r.base, files))[1]

    def sdir(self, sid):
        return os.path.join(self.r.gitdir(), "runs", sid)

    # ── B1: git configuration, index flags and replace refs ───────────────

    def test_git_diff_configuration_cannot_hide_a_masked_gate(self):
        for i, cfg in enumerate([("diff.noprefix", "true"), ("diff.mnemonicPrefix", "true"),
                                 ("color.diff", "always"), ("color.ui", "always"), ("diff.external", "/bin/true")]):
            sid = "t-cfg-%d" % i
            self.r.locked(sid, [PASSING], owner_authorizes=["CI_INTEGRITY"])
            self.r.git("config", *cfg)
            self.r.write(WF, "jobs: {}\n# run: cargo test || true\n")
            st, line = self.state(sid)
            self.assertEqual(st, "ESCALATE_TO_OWNER", "%s: %s" % (cfg, line))
            self.r.git("config", "--unset", cfg[0])
            self.r.write(WF, "jobs: {}\n")

    def test_the_owners_global_git_config_cannot_hide_a_masked_gate(self):
        cfg = os.path.join(self.parent, "gitconfig")
        with open(cfg, "w") as f:
            f.write("[diff]\n\tnoprefix = true\n\texternal = /bin/true\n")
        self.r.locked("t-glob", [PASSING], owner_authorizes=["CI_INTEGRITY"])
        self.r.write(WF, "jobs: {}\n# run: cargo test || true\n")
        rc, line = self.r.qc("verdict", "t-glob", env={"GIT_CONFIG_GLOBAL": cfg})
        self.assertIn("ESCALATE_TO_OWNER", line)

    def test_an_external_diff_cannot_keep_stale_evidence_verified(self):
        self.r.locked("t-ext", [PASSING])
        self.r.git("config", "diff.external", "/bin/true")
        self.r.write("src/app.txt", "v2\n")
        self.assertIn("VERIFIED", self.verified("t-ext", ["src/app.txt"]))
        self.r.write("src/app.txt", "v3 edited after VERIFIED\n")
        self.assertIn("stale", self.state("t-ext")[1])

    def test_index_flags_cannot_hide_a_change(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            sid = "t-idx" + flag.replace("--", "-")
            self.r.locked(sid, [PASSING])
            self.r.git("update-index", flag, CRYPTO)
            self.r.write(CRYPTO, "// a hidden crypto edit\n")
            st, line = self.state(sid)
            self.assertEqual(st, "ESCALATE_TO_OWNER", "%s: %s" % (flag, line))
            self.assertIn("CRYPTO", line)
            self.r.write(CRYPTO, "// crypto\n")
            self.r.git("update-index", flag.replace("--", "--no-"), CRYPTO)

    def test_a_replace_ref_cannot_hide_a_change(self):
        self.r.locked("t-repl", [PASSING])
        self.r.write(CRYPTO, "// unauthorized\n")
        self.r.git("add", "-A")
        tree = self.r.git("write-tree").strip()
        commit = self.r.git("commit-tree", tree, "-p", self.r.base, "-m", "x").strip()
        self.r.git("reset", "-q")
        self.r.git("replace", self.r.base, commit)
        st, line = self.state("t-repl")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)

    def test_info_exclude_cannot_hide_a_new_file(self):
        self.r.locked("t-excl", [PASSING])
        with open(os.path.join(self.r.dir, ".git/info/exclude"), "a") as f:
            f.write("crates/core-crypto/src/hidden.rs\n")
        self.r.write("crates/core-crypto/src/hidden.rs", "// hidden new crypto file\n")
        st, line = self.state("t-excl")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)

    def test_the_owners_local_settings_file_is_not_part_of_the_change(self):
        self.r.write(".claude/settings.local.json", '{"hooks": {}}\n')
        self.r.locked("t-local", [PASSING])  # lock accepts the tree
        self.r.write("src/app.txt", "v2\n")
        p = subprocess.run([PY, ".claude/qc/qc.py", "classify", "t-local"], cwd=self.r.dir, capture_output=True,
                           text=True, env=self.r.env())
        self.assertEqual(sorted(json.loads(p.stdout)["paths"]), ["src/app.txt"])
        # A tracked one is an ordinary, owner-gated path.
        self.r.git("add", "-f", ".claude/settings.local.json")
        self.assertIn("AGENT_CONTROL", self.r.qc("verdict", "t-local")[1])

    def test_a_diff_attribute_cannot_hide_added_lines(self):
        self.r.write(".gitattributes", "*.yml -diff\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-qm", "attrs")
        self.r.base = self.r.git("rev-parse", "HEAD").strip()
        self.r.locked("t-attr", [PASSING], owner_authorizes=["CI_INTEGRITY"])
        self.r.write(WF, "jobs: {}\n# run: cargo test || true\n")
        st, line = self.state("t-attr")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)

    # ── M1: rollback, delete and relock, overwritten records ──────────────

    def test_a_state_rolled_back_to_an_older_signed_copy_is_blocked(self):
        self.r.locked("t-rb", [FAILING])
        backup = os.path.join(self.parent, "state-backup.json")
        shutil.copy(os.path.join(self.sdir("t-rb"), "state.json"), backup)
        for i in range(4):
            self.r.write("src/app.txt", "a%d\n" % i)
            self.r.qc("run", "t-rb")
        self.assertEqual(self.state("t-rb")[0], "ESCALATE_TO_OWNER")
        shutil.copy(backup, os.path.join(self.sdir("t-rb"), "state.json"))
        st, line = self.state("t-rb")
        self.assertEqual(st, "BLOCKED", line)
        self.assertIn("rolled back", line)

    def test_a_rollback_cannot_erase_a_blocking_review(self):
        self.r.locked("t-rr", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write(CRYPTO, "// changed\n")
        self.r.qc("run", "t-rr")
        self.r.review("t-rr", "engineering-code-review", eng_pass(self.r.base, [CRYPTO]))
        backup = os.path.join(self.parent, "state-backup.json")
        shutil.copy(os.path.join(self.sdir("t-rr"), "state.json"), backup)
        self.assertIn("FAILED", self.r.review("t-rr", "arcium-security-review", sec(self.r.base, [CRYPTO], HIGH))[1])
        shutil.copy(backup, os.path.join(self.sdir("t-rr"), "state.json"))
        rc, line = self.r.review("t-rr", "arcium-security-review", sec(self.r.base, [CRYPTO]))
        self.assertIn("BLOCKED", line)
        self.assertEqual(self.state("t-rr")[0], "BLOCKED")
        self.assertIn("HIGH", load(os.path.join(self.sdir("t-rr"), "review-2.json"))["text"])

    def test_deleting_the_state_and_locking_again_is_refused(self):
        self.r.locked("t-dr", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-dr")
        os.remove(os.path.join(self.sdir("t-dr"), "state.json"))
        self.r.git("stash", "-u")
        rc, line = self.r.qc("lock", "t-dr")
        self.r.git("stash", "pop")
        self.assertIn("BLOCKED", line)
        self.assertIn("earlier lock", line)

    # ── m1: interruptions count; records written before a crash are kept ─

    def test_a_criterion_that_kills_its_runner_still_exhausts_the_budget(self):
        crit = {"id": "ac-kill", "description": "kills its runner",
                "command": [PY, "-c", "import os,signal\nos.kill(os.getppid(), signal.SIGKILL)"]}
        self.r.locked("t-kf", [crit])
        for i in range(5):
            self.r.write("src/app.txt", "a%d\n" % i)
            self.r.qc("run", "t-kf")
        st, line = self.state("t-kf")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)
        self.assertLessEqual(len(os.listdir(self.sdir("t-kf"))), 6)

    def test_a_failed_run_recorded_just_before_a_crash_still_counts(self):
        self.r.locked("t-kw", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        rc, _ = self.r.qc("run", "t-kw", env={"QC_TEST_CRASH_AT": "run-recorded"})
        self.assertEqual(rc, -9)
        st, line = self.state("t-kw")
        self.assertEqual(st, "FAILED", line)
        self.r.qc("run", "t-kw")
        runs = load(os.path.join(self.sdir("t-kw"), "state.json"))
        self.assertEqual([x["outcome"] for x in runs["runs"]], ["FAILED", "FAILED"])
        self.assertEqual(runs["failed_runs"], 2)

    def test_a_blocking_review_recorded_just_before_a_crash_still_counts(self):
        self.r.locked("t-kr", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write(CRYPTO, "// changed\n")
        self.r.qc("run", "t-kr")
        self.r.review("t-kr", "engineering-code-review", eng_pass(self.r.base, [CRYPTO]))
        text = sec(self.r.base, [CRYPTO], HIGH).replace(
            "ARCIUM_SECURITY_REVIEW\n", "ARCIUM_SECURITY_REVIEW\nqc_fingerprint: %s\n" % self.r.fingerprint(), 1)
        rc, _ = self.r.qc("review-record", "t-kr", "arcium-security-review", stdin=text,
                          env={"QC_TEST_CRASH_AT": "review-recorded"})
        self.assertEqual(rc, -9)
        st, line = self.state("t-kr")
        self.assertEqual(st, "FAILED", line)
        self.assertIn("HIGH", line)

    # ── m3, m5, path tokens ───────────────────────────────────────────────

    def test_a_test_runner_is_recognised_by_name_and_alias(self):
        for i, argv in enumerate([["/root/.cargo/bin/cargo", "test", "--workspace"], ["cargo", "t", "--workspace"],
                                  ["/usr/bin/python3", "-m", "pytest"]]):
            for extra in ({}, {"must_match": ["ok"], "expect_exit": 101}):
                sid = "t-rn-%d-%d" % (i, len(extra))
                self.r.spec(sid, [dict({"id": "ac-x", "description": "x", "command": argv}, **extra)])
                rc, line = self.r.qc("spec-check", sid)
                self.assertIn("BLOCKED", line, "%s %s" % (argv, extra))

    def test_activating_another_loop_cannot_end_one_mid_repair(self):
        self.r.locked("t-a1", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-a1")
        self.r.qc("activate", "t-a1")
        self.r.spec("t-a2", [PASSING])
        rc, line = self.r.qc("activate", "t-a2")
        self.assertIn("FAILED", line)
        self.assertEqual(load(os.path.join(self.r.gitdir(), "active.json"))["spec_id"], "t-a1")
        for i in range(3):
            self.r.write("src/app.txt", "v%d\n" % (i + 3))
            self.r.qc("run", "t-a1")
        self.assertEqual(self.state("t-a1")[0], "ESCALATE_TO_OWNER")
        rc, line = self.r.qc("activate", "t-a2")
        self.assertIn("ESCALATE_TO_OWNER", line, "an escalation is not hidden by switching loops")
        self.assertEqual(load(os.path.join(self.r.gitdir(), "active.json"))["spec_id"], "t-a1")

    def test_a_review_must_name_each_path_as_a_whole(self):
        self.r.locked("t-tok", [PASSING])
        self.r.write("src/a", "new\n")
        self.r.qc("run", "t-tok")
        rc, line = self.r.review("t-tok", "engineering-code-review", eng_pass(self.r.base, ["src/ab.txt"]))
        self.assertIn("missing", line)
        self.assertIn("src/a", line)

    # ── m4: the guard and the reviewer's own record ───────────────────────

    def test_the_guard_lets_a_review_record_through_but_not_a_disguised_command(self):
        self.r.locked("t-g", [PASSING])
        self.r.qc("activate", "t-g")
        body = "KARPATHY_REVIEW_RESULT\ntests_run: python3 -m unittest -> 63 OK, read CLAUDE.md .claude/qc/qc.py\n"
        ok = "python3 .claude/qc/qc.py review-record t-g engineering-code-review <<'EOF'\n%sEOF\n" % body
        rc, out, _ = self.r.hook("pre-tool", {"tool_name": "Bash", "tool_input": {"command": ok}})
        self.assertEqual(out, "")
        for bad in (ok + "rm CLAUDE.md\n",
                    "python3 .claude/qc/qc.py review-record t-g engineering-code-review <<'EOF'\nx\nEOF\n"
                    "rm CLAUDE.md\nEOF\n",
                    "python3 .claude/qc/qc.py review-record t-g engineering-code-review <<EOF\n$(rm CLAUDE.md)\nEOF\n"):
            rc, out, _ = self.r.hook("pre-tool", {"tool_name": "Bash", "tool_input": {"command": bad}})
            self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny", bad)

    # ── M2 and m7: what a run depends on outside the tree, and its tree ───

    def test_a_cargo_configuration_above_the_repository_is_not_verified(self):
        fake = os.path.join(self.parent, "bin", "cargo-qc-fake")
        os.makedirs(os.path.dirname(fake))
        with open(fake, "w") as f:
            f.write("#!/bin/sh\necho 'test result: ok. 1 passed; 0 failed'\n")
        os.chmod(fake, 0o755)
        crit = {"id": "ac-cargo", "description": "a cargo-named program", "command": [fake, "test"],
                "must_match": [r"test result: ok\. [1-9][0-9]* passed; 0 failed"]}
        self.r.locked("t-cfgup", [crit])
        self.r.write("src/app.txt", "v2\n")
        os.makedirs(os.path.join(self.parent, ".cargo"))
        with open(os.path.join(self.parent, ".cargo", "config.toml"), "w") as f:
            f.write("[target.x86_64-unknown-linux-gnu]\nrunner = \"echo\"\n")
        rc, line = self.r.qc("run", "t-cfgup")
        self.assertIn("NOT_VERIFIED", line)
        self.assertIn("Cargo configuration outside the repository", line)
        ev = load(os.path.join(self.sdir("t-cfgup"), "run-1.json"))
        self.assertEqual(ev["results"][0]["toolchain"]["program"]["path"], os.path.realpath(fake))

    def test_a_run_records_the_tree_it_verified(self):
        self.r.locked("t-tree", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.write("src/new.txt", "new\n")
        self.r.qc("run", "t-tree")
        tree = load(os.path.join(self.sdir("t-tree"), "run-1.json"))["tree"]
        self.assertRegex(tree, r"^[0-9a-f]{40}$")
        self.assertEqual(self.r.git("show", "%s:src/app.txt" % tree), "v2\n")
        self.assertEqual(sorted(self.r.git("diff", "--name-only", self.r.base, tree).split()),
                         ["src/app.txt", "src/new.txt"])
        self.assertEqual(self.r.git("status", "--porcelain", "--untracked-files=all").split(),
                         ["M", "src/app.txt", "??", "src/new.txt"], "the index and tree are untouched")


class ThirdRoundTest(unittest.TestCase):
    """Holes a second independent review found in 53fce83; each test fails there."""

    def setUp(self):
        self.parent = tempfile.mkdtemp(prefix="qc-parent-")
        self.r = Repo(parent=self.parent)

    def tearDown(self):
        shutil.rmtree(self.parent, ignore_errors=True)

    def state(self, sid):
        rc, line = self.r.qc("verdict", sid)
        return line.split("|")[0].replace("QC_STATE:", "").strip(), line

    def paths(self, sid):
        p = subprocess.run([PY, ".claude/qc/qc.py", "classify", sid], cwd=self.r.dir, capture_output=True,
                           text=True, env=self.r.env())
        return sorted(json.loads(p.stdout)["paths"])

    def verified(self, sid, files):
        self.r.qc("run", sid)
        self.r.review(sid, "engineering-code-review", eng_pass(self.r.base, files))
        return self.r.review(sid, "arcium-security-review", sec(self.r.base, files))[1]

    # X1: an ignore rule written during the task hides nothing

    def test_a_self_ignoring_gitignore_cannot_hide_a_cargo_config(self):
        self.r.locked("t-x1a", [PASSING])
        self.r.write(".cargo/.gitignore", "*\n")
        self.r.write(".cargo/config.toml", "[target.x86_64-unknown-linux-gnu]\nrunner = \"true\"\n")
        self.assertEqual(self.paths("t-x1a"), [".cargo/.gitignore", ".cargo/config.toml"])
        st, line = self.state("t-x1a")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)
        self.assertIn("SUPPLY_CHAIN", line)

    def test_a_self_ignoring_gitignore_cannot_hide_a_crypto_file(self):
        self.r.locked("t-x1b", [PASSING])
        self.r.write("crates/core-crypto/src/.gitignore", ".gitignore\nhidden.rs\n")
        self.r.write("crates/core-crypto/src/hidden.rs", "// hidden\n")
        self.assertIn("crates/core-crypto/src/hidden.rs", self.paths("t-x1b"))
        self.assertEqual(self.state("t-x1b")[0], "ESCALATE_TO_OWNER")

    def test_a_new_directory_ignoring_its_contents_is_listed(self):
        self.r.locked("t-x1c", [PASSING])
        self.r.write("newdir/.gitignore", "*\n")
        self.r.write("newdir/hidden.txt", "x\n")
        self.assertEqual(self.paths("t-x1c"), ["newdir/.gitignore", "newdir/hidden.txt"])

    def test_an_edited_tracked_gitignore_hides_nothing_but_its_own_rules_still_apply(self):
        self.r.write(".gitignore", "target/\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-qm", "ignore")
        self.r.base = self.r.git("rev-parse", "HEAD").strip()
        self.r.locked("t-x1d", [PASSING])
        self.r.write("target/build.out", "x\n")
        self.assertEqual(self.paths("t-x1d"), [], "the repository's own unchanged rule still ignores target/")
        self.r.write(".gitignore", "target/\nsrc/secret.txt\n")
        self.r.write("src/secret.txt", "x\n")
        self.assertIn("src/secret.txt", self.paths("t-x1d"))
        self.assertNotIn("target/build.out", self.paths("t-x1d"), "target/ is still the repository's own rule")

    # X2: Claude Code's local settings do not change under a locked loop

    def test_local_settings_changed_after_lock_escalate(self):
        self.r.write(".claude/settings.local.json", '{"hooks": {}}\n')
        self.r.locked("t-x2", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.assertIn("VERIFIED", self.verified("t-x2", ["src/app.txt"]))
        self.r.write(".claude/settings.local.json", '{"permissions": {"defaultMode": "bypassPermissions"}}\n')
        st, line = self.state("t-x2")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)
        self.assertIn("settings.local.json", line)

    # X3: the review-record exemption ends where bash ends the heredoc

    def test_a_tab_stripped_heredoc_cannot_smuggle_a_command(self):
        self.r.locked("t-x3", [PASSING])
        self.r.qc("activate", "t-x3")
        cmd = ("python3 .claude/qc/qc.py review-record t-x3 engineering-code-review <<-'EOF'\n"
               "KARPATHY_REVIEW_RESULT\n\tEOF\ngit push origin main\nEOF\n")
        rc, out, _ = self.r.hook("pre-tool", {"tool_name": "Bash", "tool_input": {"command": cmd}})
        self.assertEqual(json.loads(out or "{}").get("hookSpecificOutput", {}).get("permissionDecision"), "deny")

    # X4, X5: contents a hash of the paths would not see

    def test_an_untracked_nested_repository_is_blocked(self):
        self.r.locked("t-x4", [PASSING])
        subprocess.run(["git", "init", "-q", os.path.join(self.r.dir, "inner")], check=True)
        self.r.write("inner/main.rs", "x\n")
        st, line = self.state("t-x4")
        self.assertEqual(st, "BLOCKED", line)
        self.assertIn("nested", line)

    def test_a_link_to_a_directory_out_of_the_clone_is_blocked(self):
        os.makedirs(os.path.join(self.parent, "outdir"))
        self.r.locked("t-f7", [PASSING])
        os.symlink(os.path.join(self.parent, "outdir"), os.path.join(self.r.dir, "src/linkdir"))
        st, line = self.state("t-f7")
        self.assertEqual(st, "BLOCKED", line)
        self.assertIn("outside the clone", line)

    def test_a_link_out_of_the_clone_follows_its_target(self):
        outside = os.path.join(self.parent, "outside.txt")
        with open(outside, "w") as f:
            f.write("v1\n")
        self.r.locked("t-x5", [PASSING])
        os.symlink(outside, os.path.join(self.r.dir, "src/link.txt"))
        self.assertIn("VERIFIED", self.verified("t-x5", ["src/link.txt"]))
        with open(outside, "w") as f:
            f.write("v2\n")
        self.assertIn("stale", self.state("t-x5")[1])

    # X6: an escalation cannot be silenced in two steps either

    def test_an_escalated_loop_cannot_be_deactivated_by_the_agent(self):
        self.r.locked("t-x6", [FAILING])
        for i in range(4):
            self.r.write("src/app.txt", "a%d\n" % i)
            self.r.qc("run", "t-x6")
        self.r.qc("activate", "t-x6")
        rc, line = self.r.qc("deactivate")
        self.assertIn("ESCALATE_TO_OWNER", line)
        self.assertTrue(os.path.exists(os.path.join(self.r.gitdir(), "active.json")))
        self.r.spec("t-x6b", [PASSING])
        self.assertIn("ESCALATE_TO_OWNER", self.r.qc("activate", "t-x6b")[1])

    # X7: the recorded tree survives garbage collection

    def test_the_recorded_tree_survives_gc(self):
        self.r.locked("t-x7", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-x7")
        tree = load(os.path.join(self.r.gitdir(), "runs/t-x7/run-1.json"))["tree"]
        self.r.git("gc", "-q", "--prune=now")
        self.assertEqual(self.r.git("show", "%s:src/app.txt" % tree), "v2\n")

    # N4, N9, N11

    def test_a_directory_replaced_by_a_file_is_a_change_not_an_internal_error(self):
        self.r.locked("t-n4", [PASSING])
        shutil.rmtree(os.path.join(self.r.dir, "src"))
        self.r.write("src", "now a file\n")
        st, line = self.state("t-n4")
        self.assertNotIn("internal error", line)
        self.assertIn("src/app.txt", self.paths("t-n4"))

    def test_a_spec_edited_after_a_crash_is_reported_as_a_spec_change(self):
        self.r.locked("t-n9", [FAILING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-n9", env={"QC_TEST_CRASH_AT": "run-recorded"})
        with open(self.r.qc("spec-path", "t-n9")[1]) as f:
            spec = json.load(f)
        spec["title"] = "edited"
        with open(self.r.qc("spec-path", "t-n9")[1], "w") as f:
            json.dump(spec, f)
        self.assertIn("changed after it was locked", self.state("t-n9")[1])

    def test_a_cargo_runner_variable_is_not_verified(self):
        fake = os.path.join(self.parent, "bin", "cargo-qc-fake")
        os.makedirs(os.path.dirname(fake))
        with open(fake, "w") as f:
            f.write("#!/bin/sh\necho 'test result: ok. 1 passed; 0 failed'\n")
        os.chmod(fake, 0o755)
        crit = {"id": "ac-cargo", "description": "a cargo-named program", "command": [fake, "test"],
                "must_match": [r"test result: ok\. [1-9][0-9]* passed; 0 failed"]}
        self.r.locked("t-n11", [crit])
        self.r.write("src/app.txt", "v2\n")
        rc, line = self.r.qc("run", "t-n11", env={"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": "true"})
        self.assertIn("NOT_VERIFIED", line)
        self.assertIn("RUNNER", line)


if __name__ == "__main__":
    unittest.main()
