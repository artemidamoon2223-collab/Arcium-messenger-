"""Regression tests for the fifth and sixth review rounds of .claude/qc: hook
input that cannot be used, a clone the guard cannot inspect, early
deactivation, git state read by criteria, and the mutants M04, M07 and M17.

Run with the other tests: `python3 -B -m unittest discover -s .claude/qc/tests`.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import types
import unittest

from test_qc import HIGH, PASSING, PY, Repo, eng_pass, load, sec

CRYPTO = "crates/core-crypto/src/x.rs"
GIT_SHOW = {"id": "ac-index", "description": "reads the staged file", "command": ["git", "show", ":src/app.txt"],
            "must_match": ["^v2$"]}


class FinalTest(unittest.TestCase):
    def setUp(self):
        self.parent = tempfile.mkdtemp(prefix="qc-parent-")
        self.r = Repo(parent=self.parent)

    def tearDown(self):
        shutil.rmtree(self.parent, ignore_errors=True)

    def state(self, sid):
        rc, line = self.r.qc("verdict", sid)
        return line.split("|")[0].replace("QC_STATE:", "").strip(), line

    def sdir(self, sid):
        return os.path.join(self.r.gitdir(), "runs", sid)

    def verified(self, sid, files):
        self.r.qc("run", sid)
        self.r.review(sid, "engineering-code-review", eng_pass(self.r.base, files))
        line = self.r.review(sid, "arcium-security-review", sec(self.r.base, files))[1]
        self.assertIn("QC_STATE: VERIFIED", line)

    def raw_hook(self, event, data, extra_env=None):
        """Run the hook as hooks.candidate.json does, with raw bytes on stdin."""
        env = dict(self.r.env(), **(extra_env or {}))
        p = subprocess.run([PY, "-I", "-B", os.path.join(self.r.dir, ".claude/qc/hooks.py"), event],
                           cwd=self.r.dir, capture_output=True, input=data, env=env)
        return p.returncode, p.stdout.decode().strip(), p.stderr.decode().strip()

    def active_not_verified(self):
        self.r.locked("t-in", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-in")  # passes; reviews pending: NOT_VERIFIED
        self.r.qc("activate", "t-in")
        self.assertEqual(self.state("t-in")[0], "NOT_VERIFIED")

    # ── hook input that cannot be used fails closed while a loop is active ──

    BAD_INPUTS = {
        "oversized": None,  # built in the test: over 16 MiB of valid JSON
        "truncated": b'{"tool_name": "Bash", "tool_input": {"command": "git push origin HEAD"',
        "not an object": b'["git push"]',
        "not utf-8": b'{"last_assistant_message": "\xff\xfe QC_STATE: VERIFIED"}',
        "too deeply nested": b"[" * 200000,
        "empty": b"",
    }

    def bad_inputs(self, payload):
        for name, raw in self.BAD_INPUTS.items():
            if raw is None:
                big = dict(payload, padding="x" * (17 << 20))
                raw = json.dumps(big).encode()
            yield name, raw

    def test_unusable_input_while_a_loop_is_active_fails_closed(self):
        self.active_not_verified()
        stop = {"stop_hook_active": False, "last_assistant_message": "QC_STATE: VERIFIED | done"}
        pre = {"tool_name": "Bash", "tool_input": {"command": "git push origin HEAD"}}
        task = {"task_subject": "[qc] t"}
        for name, raw in self.bad_inputs(stop):
            rc, out, _ = self.raw_hook("stop", raw)
            self.assertEqual(json.loads(out or "{}").get("decision"), "block", name)
        for name, raw in self.bad_inputs(pre):
            rc, out, _ = self.raw_hook("pre-tool", raw)
            self.assertEqual(json.loads(out or "{}").get("hookSpecificOutput", {}).get("permissionDecision"),
                             "deny", name)
        for name, raw in self.bad_inputs(task):
            rc, out, err = self.raw_hook("task-completed", raw)
            self.assertEqual(rc, 2, name)

    def test_unusable_input_blocks_a_stop_only_once(self):
        self.active_not_verified()
        raw = json.dumps({"stop_hook_active": True, "last_assistant_message": "QC_STATE: VERIFIED",
                          "padding": "x" * (17 << 20)}).encode()
        rc, out, _ = self.raw_hook("stop", raw)
        out = json.loads(out or "{}")
        self.assertNotEqual(out.get("decision"), "block")
        self.assertIn("QC WARNING", out.get("systemMessage", ""))

    def test_unusable_input_with_no_loop_active_does_nothing(self):
        self.r.locked("t-idle", [PASSING])
        for event in ("stop", "pre-tool", "task-completed"):
            for name, raw in self.bad_inputs({"x": 1}):
                self.assertEqual(self.raw_hook(event, raw), (0, "", ""), (event, name))

    # ── a clone the guard cannot inspect, while an activation record exists there ──

    def assert_fails_closed(self, extra_env=None):
        payloads = {"stop": {"stop_hook_active": False, "last_assistant_message": "QC_STATE: VERIFIED | done"},
                    "pre-tool": {"tool_name": "Bash", "tool_input": {"command": "git push origin HEAD"}},
                    "task-completed": {"task_subject": "[qc] t"}}
        for event, payload in payloads.items():
            rc, out, err = self.raw_hook(event, json.dumps(payload).encode(), extra_env)
            got = json.loads(out or "{}")
            ok = {"stop": got.get("decision") == "block",
                  "pre-tool": got.get("hookSpecificOutput", {}).get("permissionDecision") == "deny",
                  "task-completed": rc == 2}[event]
            self.assertTrue(ok, (event, rc, out, err))

    def no_git_path(self):
        empty = os.path.join(self.parent, "empty-bin")
        os.makedirs(empty, exist_ok=True)
        return {"PATH": empty}

    def test_git_missing_while_a_loop_is_active_fails_closed(self):
        self.active_not_verified()
        self.assert_fails_closed(self.no_git_path())

    def test_git_missing_with_no_loop_active_does_nothing(self):
        self.r.locked("t-idle", [PASSING])
        self.assertEqual(self.raw_hook("pre-tool", b'{"tool_name": "Bash", "tool_input": {"command": "ls"}}',
                                       self.no_git_path()), (0, "", ""))

    def test_a_qc_tool_that_does_not_load_fails_closed(self):
        self.active_not_verified()
        with open(os.path.join(self.r.dir, ".claude/qc/qc.py"), "a") as f:
            f.write("\nthis is not python\n")
        self.assert_fails_closed()

    def test_a_deadline_while_finding_the_loop_fails_closed(self):
        self.active_not_verified()
        mod = types.ModuleType("hooks_under_test")
        path = os.path.join(self.r.dir, ".claude/qc/hooks.py")
        mod.__file__ = path
        with open(path) as f:
            exec(compile(f.read(), path, "exec"), mod.__dict__)
        mod.DEADLINE["pre-tool"] = 1
        mod.qc.repo_root = lambda start=None: time.sleep(30) or self.r.dir  # longer than any hook timeout
        t0 = time.time()
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mod.main("pre-tool", {"cwd": self.r.dir, "tool_name": "Bash", "tool_input": {"command": "git push"}})
        self.assertLess(time.time() - t0, 10, "the deadline ends the lookup instead of moving to the next clone")
        self.assertEqual(json.loads(buf.getvalue() or "{}").get("hookSpecificOutput", {}).get("permissionDecision"),
                         "deny", buf.getvalue())

    def undecodable_gitfile_dir(self):
        d = os.path.join(self.parent, "odd")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, ".git"), "wb") as f:
            f.write(b"\xff\xfe not a gitdir line \x80")
        return d

    def test_an_undecodable_git_file_in_the_cwd_does_not_hide_the_loop(self):
        self.active_not_verified()
        odd = self.undecodable_gitfile_dir()
        payload = {"tool_name": "Bash", "tool_input": {"command": "git push origin HEAD"}, "cwd": odd}
        rc, out, err = self.raw_hook("pre-tool", json.dumps(payload).encode(), {"CLAUDE_PROJECT_DIR": self.r.dir})
        self.assertEqual((rc, json.loads(out or "{}").get("hookSpecificOutput", {}).get("permissionDecision")),
                         (0, "deny"), err)

    def test_an_undecodable_git_file_with_no_loop_active_does_nothing(self):
        self.r.locked("t-idle", [PASSING])
        odd = self.undecodable_gitfile_dir()
        payload = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": odd}
        self.assertEqual(self.raw_hook("pre-tool", json.dumps(payload).encode(), {"CLAUDE_PROJECT_DIR": odd}),
                         (0, "", ""))

    def test_input_that_never_ends_fails_closed(self):
        self.active_not_verified()
        with subprocess.Popen([PY, "-I", "-B", os.path.join(self.r.dir, ".claude/qc/hooks.py"), "pre-tool"],
                              cwd=self.r.dir, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=self.r.env()) as p:
            p.stdin.write(b'{"tool_name": "Bash", ')
            p.stdin.flush()
            try:
                p.wait(timeout=30)  # the hook answers without waiting for the rest of its input
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
                self.fail("the hook waited for its input past every deadline")
            finally:
                p.stdin.close()
            out = p.stdout.read().decode()
        self.assertEqual(json.loads(out or "{}").get("hookSpecificOutput", {}).get("permissionDecision"), "deny")

    # ── deactivation only once VERIFIED ──

    def test_a_loop_is_not_deactivated_before_its_result(self):
        self.active_not_verified()
        rc, line = self.r.qc("deactivate")
        self.assertIn("NOT_VERIFIED", line)
        self.assertTrue(os.path.exists(os.path.join(self.r.gitdir(), "active.json")))
        self.r.spec("t-other", [PASSING])
        rc, line = self.r.qc("activate", "t-other")
        self.assertIn("NOT_VERIFIED", line)
        self.assertEqual(load(os.path.join(self.r.gitdir(), "active.json"))["spec_id"], "t-in")
        # The result reached: now it may be switched off.
        self.r.review("t-in", "engineering-code-review", eng_pass(self.r.base, ["src/app.txt"]))
        self.r.review("t-in", "arcium-security-review", sec(self.r.base, ["src/app.txt"]))
        self.assertEqual(self.state("t-in")[0], "VERIFIED")
        rc, line = self.r.qc("deactivate")
        self.assertIn("no QC loop active", line)
        self.assertFalse(os.path.exists(os.path.join(self.r.gitdir(), "active.json")))

    def test_an_unreadable_activation_is_not_deactivated_by_the_agent(self):
        self.active_not_verified()
        with open(os.path.join(self.r.gitdir(), "active.json"), "w") as f:
            f.write("{not json")
        rc, line = self.r.qc("deactivate")
        self.assertIn("BLOCKED", line)
        self.assertTrue(os.path.exists(os.path.join(self.r.gitdir(), "active.json")))
        self.r.spec("t-other", [PASSING])
        self.assertIn("BLOCKED", self.r.qc("activate", "t-other")[1])

    # ── git state a criterion may read is part of the fingerprint ──

    def test_a_staged_change_makes_the_evidence_stale(self):
        self.r.locked("t-idx", [GIT_SHOW], owner_authorizes=[])
        self.r.write("src/app.txt", "v2\n")
        self.r.git("add", "src/app.txt")
        self.verified("t-idx", ["src/app.txt"])
        self.r.write("src/app.txt", "bad\n")
        self.r.git("add", "src/app.txt")
        self.r.write("src/app.txt", "v2\n")  # the disk is as verified, the index is not
        st, line = self.state("t-idx")
        self.assertEqual(st, "NOT_VERIFIED", line)
        self.assertIn("stale", line)

    def test_a_config_or_attributes_change_makes_the_evidence_stale(self):
        self.r.locked("t-cfg", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.verified("t-cfg", ["src/app.txt"])
        self.r.git("config", "diff.qc.textconv", "cat")
        self.assertIn("stale", self.state("t-cfg")[1])
        self.r.git("config", "--unset", "diff.qc.textconv")
        self.assertEqual(self.state("t-cfg")[0], "VERIFIED", "the same config again is the same tree")
        os.makedirs(os.path.join(self.r.dir, ".git/info"), exist_ok=True)
        with open(os.path.join(self.r.dir, ".git/info/attributes"), "w") as f:
            f.write("*.txt diff=qc\n")
        self.assertIn("stale", self.state("t-cfg")[1])

    def test_a_criterion_running_git_status_is_not_a_tree_change(self):
        status = {"id": "ac-status", "description": "runs git status, which may refresh the index",
                  "command": ["git", "status", "--porcelain"]}
        self.r.locked("t-st", [PASSING, status])
        self.r.write("src/app.txt", "v2\n")
        self.r.git("add", "src/app.txt")  # the index matches the disk ...
        past = time.time() - 3600
        os.utime(os.path.join(self.r.dir, "src/app.txt"), (past, past))  # ... but its stat data is stale
        rc, line = self.r.qc("run", "t-st")
        self.assertNotIn("changed while the criteria ran", line)
        self.assertIn("review pending", line)

    def test_read_only_git_commands_do_not_make_the_evidence_stale(self):
        self.r.locked("t-ro", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.verified("t-ro", ["src/app.txt"])
        os.utime(os.path.join(self.r.dir, "src/app.txt"))
        self.r.git("status", "--porcelain")
        self.r.git("diff")
        self.assertEqual(self.state("t-ro")[0], "VERIFIED")

    # ── mutants that survived the earlier tests ──

    def test_m07_a_blocking_review_adopted_after_a_crash_costs_a_round(self):
        self.r.locked("t-m07", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write(CRYPTO, "// changed\n")
        self.r.qc("run", "t-m07")
        self.r.review("t-m07", "engineering-code-review", eng_pass(self.r.base, [CRYPTO]))
        text = sec(self.r.base, [CRYPTO], HIGH).replace(
            "ARCIUM_SECURITY_REVIEW\n", "ARCIUM_SECURITY_REVIEW\nqc_fingerprint: %s\n" % self.r.fingerprint(), 1)
        rc, _ = self.r.qc("review-record", "t-m07", "arcium-security-review", stdin=text,
                          env={"QC_TEST_CRASH_AT": "review-recorded"})
        self.assertEqual(rc, -9)
        self.assertEqual(self.state("t-m07")[0], "FAILED")
        self.r.write(CRYPTO, "// repaired\n")
        self.r.qc("run", "t-m07")  # settles what the crashed review-record left, and saves it
        self.assertEqual(load(os.path.join(self.sdir("t-m07"), "state.json"))["failed_runs"], 1,
                         "the blocking review recorded before the crash costs its round")

    def test_m04_a_record_planted_during_a_run_is_never_overwritten(self):
        planted = os.path.join(self.sdir("t-m04"), "run-1.json")
        forger = {"id": "ac-forge", "description": "writes its own run record while it runs",
                  "command": [PY, "-c", "open(%r, 'w').write('{\"planted\": true}')\n"
                                        "print('test result: ok. 3 passed; 0 failed')" % planted],
                  "must_match": [r"test result: ok\. [1-9][0-9]* passed; 0 failed"]}
        self.r.locked("t-m04", [forger])
        self.r.qc("run", "t-m04")
        with open(planted) as f:
            self.assertEqual(json.load(f), {"planted": True}, "an existing record is never overwritten")
        self.assertNotEqual(self.state("t-m04")[0], "VERIFIED")

    def test_m17_a_tree_git_stored_differently_is_not_recorded(self):
        mod = types.ModuleType("qc_under_test")
        path = os.path.join(self.r.dir, ".claude/qc/qc.py")
        mod.__file__ = path
        with open(path) as f:
            exec(compile(f.read(), path, "exec"), mod.__dict__)
        real_git = mod.git

        def lying_git(root, *args, **kw):
            out = real_git(root, *args, **kw)
            if args[:1] == ("hash-object",):
                return out.replace(out.strip()[:4], "0000", 1)
            return out
        mod.git = lying_git
        self.r.write("src/app.txt", "v2\n")
        with self.assertRaises(mod.QcError) as cm:
            mod.write_tree(self.r.dir, mod.listed_paths(self.r.dir, "HEAD"))
        self.assertEqual(cm.exception.state, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
