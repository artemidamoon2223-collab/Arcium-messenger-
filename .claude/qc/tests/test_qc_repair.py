"""Regression tests for the fourth review round of .claude/qc (B1, M1 and the
mutants the earlier tests let survive). Each test fails on 8b8caa3.

Run with the other tests: `python3 -B -m unittest discover -s .claude/qc/tests`.
"""

import contextlib
import io
import json
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest

from test_qc import PASSING, PY, REPO, Repo, eng_pass, sec

FAILING_ONCE = {"id": "ac-flaky", "description": "fails while a flag file exists",
                "command": [PY, "-c", "import os,sys\nif os.path.exists('flag.fail'): sys.exit(1)\n"
                                      "print('test result: ok. 3 passed; 0 failed')"],
                "must_match": [r"test result: ok\. [1-9][0-9]* passed; 0 failed"]}


class RepairTest(unittest.TestCase):
    def setUp(self):
        self.parent = tempfile.mkdtemp(prefix="qc-parent-")
        self.r = Repo(parent=self.parent)

    def tearDown(self):
        shutil.rmtree(self.parent, ignore_errors=True)

    def commit(self, files):
        for rel, text in files.items():
            self.r.write(rel, text)
        self.r.git("add", "-A")
        self.r.git("commit", "-qm", "more")
        self.r.base = self.r.git("rev-parse", "HEAD").strip()

    def state(self, sid):
        rc, line = self.r.qc("verdict", sid)
        return line.split("|")[0].replace("QC_STATE:", "").strip(), line

    def paths(self, sid):
        p = subprocess.run([PY, ".claude/qc/qc.py", "classify", sid], cwd=self.r.dir, capture_output=True,
                           text=True, env=self.r.env())
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return json.loads(p.stdout)

    def verified(self, sid, files, security=True):
        rc, line = self.r.qc("run", sid)
        self.r.review(sid, "engineering-code-review", eng_pass(self.r.base, files))
        if security:
            line = self.r.review(sid, "arcium-security-review", sec(self.r.base, files))[1]
        else:
            line = self.state(sid)[1]
        self.assertIn("QC_STATE: VERIFIED", line)
        return line

    def decision(self, out):
        return json.loads(out or "{}").get("hookSpecificOutput", {}).get("permissionDecision")

    # B1: a rule already in the repository's tracked .gitignore hides nothing outside the trusted
    # build directories (P1, P3).

    def test_p1_a_file_under_an_existing_ignore_rule_is_part_of_the_tree(self):
        self.commit({".gitignore": "Cargo.lock\n!/Cargo.lock\nbuild/\n*.apk\n"})
        self.r.locked("t-p1", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write("crates/core-crypto/tests/Cargo.lock/inner.rs", "#[test] fn t() {}\n")
        self.assertIn("crates/core-crypto/tests/Cargo.lock/inner.rs", self.paths("t-p1")["paths"])
        self.verified("t-p1", ["crates/core-crypto/tests/Cargo.lock/inner.rs"])
        self.r.write("crates/core-crypto/tests/Cargo.lock/inner.rs", "#[test] fn t() { panic!() }\n")
        st, line = self.state("t-p1")
        self.assertEqual(st, "NOT_VERIFIED", line)
        self.assertIn("stale", line)

    def test_p3_files_under_existing_ignore_rules_reach_the_owner_gates(self):
        self.commit({".gitignore": "build/\n.codegraph/\n*.apk\n.env\n",
                     "arcium-psi/Anchor.toml": "x\n"})
        self.r.locked("t-p3", [PASSING])
        hidden = ["crates/core-crypto/src/build/k.rs", "arcium-psi/.env", ".claude/.codegraph/x.md",
                  "crates/mobile-ffi/src/contacts.apk"]
        for rel in hidden:
            self.r.write(rel, "x\n")
        cls = self.paths("t-p3")
        self.assertEqual(sorted(cls["paths"]), sorted(hidden))
        self.assertTrue({"CRYPTO", "PSI", "AGENT_CONTROL"} <= set(cls["owner_gated"]), cls)
        st, line = self.state("t-p3")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)

    def test_the_trusted_build_directories_stay_out_of_the_tree(self):
        self.r.locked("t-build", [PASSING])
        fp = self.r.fingerprint()
        for rel in ("target/debug/deps/x.rlib", "android/app/build/out.apk", "arcium-psi/tests/node_modules/m.js"):
            self.r.write(rel, "x\n")
        self.assertEqual(self.r.fingerprint(), fp, "build output must not change the fingerprint")
        self.assertEqual(self.paths("t-build")["paths"], {})
        self.r.write("crates/target/x.rs", "x\n")  # a directory named target elsewhere is not trusted
        self.assertIn("crates/target/x.rs", self.paths("t-build")["paths"])

    def test_a_link_named_like_a_trusted_directory_is_not_trusted(self):
        os.makedirs(os.path.join(self.r.dir, "src/real"))
        self.r.write("src/real/x.rs", "x\n")
        self.commit({})
        self.r.locked("t-trlink", [PASSING])
        os.symlink("src/real", os.path.join(self.r.dir, "target"))
        self.assertIn("target", self.paths("t-trlink")["paths"])

    def test_rust_source_taken_from_a_build_directory_escalates(self):
        self.r.locked("t-incl", [PASSING], owner_authorizes=["CRYPTO"])
        self.r.write("crates/core-crypto/src/y.rs", '#[path = "../../../target/gen.rs"]\nmod gen;\n')
        st, line = self.state("t-incl")
        self.assertEqual(st, "ESCALATE_TO_OWNER", line)
        self.assertIn("BUILD_OUTPUT_INCLUDE", line)

    # P4: a link into a location whose contents are not listed follows its target

    def test_p4_a_link_into_a_trusted_build_directory_follows_its_target(self):
        self.r.write("target/gen.rs", "v1\n")
        self.r.locked("t-p4", [PASSING])
        os.symlink("../target/gen.rs", os.path.join(self.r.dir, "src/gen.rs"))
        fp = self.r.fingerprint()
        self.r.write("target/gen.rs", "v2\n")
        self.assertNotEqual(self.r.fingerprint(), fp, "the link's target is part of what ran")

    def test_p4_a_link_into_git_follows_its_target(self):
        self.r.locked("t-p4g", [PASSING])
        os.symlink("../.git/description", os.path.join(self.r.dir, "src/desc"))
        fp = self.r.fingerprint()
        with open(os.path.join(self.r.dir, ".git/description"), "a") as f:
            f.write("changed\n")
        self.assertNotEqual(self.r.fingerprint(), fp)

    def test_p4_a_link_to_a_directory_in_git_is_blocked(self):
        self.r.locked("t-p4h", [PASSING])
        os.symlink("../.git/hooks", os.path.join(self.r.dir, "src/hooks"))
        st, line = self.state("t-p4h")
        self.assertEqual(st, "BLOCKED", line)
        self.assertIn(".git", line)

    def test_p4_a_link_to_a_directory_in_a_trusted_build_directory_is_blocked(self):
        self.r.write("target/gen/x.rs", "v1\n")
        self.r.locked("t-p4d", [PASSING])
        os.symlink("../target/gen", os.path.join(self.r.dir, "src/gen"))
        st, line = self.state("t-p4d")
        self.assertEqual(st, "BLOCKED", line)
        self.assertIn("trusted build directory", line)

    # M1: gitlinks (P2)

    def test_p2_an_added_embedded_repository_is_blocked(self):
        self.r.locked("t-p2", [PASSING], owner_authorizes=["CRYPTO"])
        inner = os.path.join(self.r.dir, "crates/core-crypto/tests/sub")
        subprocess.run(["git", "init", "-q", inner], check=True)
        self.r.write("crates/core-crypto/tests/sub/inner.rs", "x\n")
        subprocess.run(["git", "-C", inner, "add", "-A"], check=True)
        subprocess.run(["git", "-C", inner, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"],
                       check=True)
        subprocess.run(["git", "-C", self.r.dir, "add", "crates/core-crypto/tests/sub"], check=True,
                       capture_output=True)
        st, line = self.state("t-p2")
        self.assertEqual(st, "BLOCKED", line)
        shutil.rmtree(os.path.join(inner, ".git"))  # the gitlink stays in the index without its .git
        st, line = self.state("t-p2")
        self.assertEqual(st, "BLOCKED", line)
        self.assertIn("gitlink", line)

    def test_a_gitlink_in_the_base_tree_is_blocked(self):
        sha = self.r.base
        self.r.git("update-index", "--add", "--cacheinfo", "160000,%s,vendor/sub" % sha)
        self.r.git("commit", "-qm", "gitlink")
        self.r.base = self.r.git("rev-parse", "HEAD").strip()
        self.r.spec("t-gl", [PASSING])
        rc, line = self.r.qc("lock", "t-gl")
        self.assertIn("BLOCKED", line)
        self.assertIn("gitlink", line)

    # Mutants that survived the earlier tests

    def test_m26_evidence_from_another_tree_is_stale_even_with_no_change_left(self):
        self.r.locked("t-m26", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.verified("t-m26", ["src/app.txt"])
        self.r.write("src/app.txt", "v1\n")  # back to the base: nothing left to review
        st, line = self.state("t-m26")
        self.assertEqual(st, "NOT_VERIFIED", line)
        self.assertIn("stale", line)

    def test_m09_a_review_quoting_another_fingerprint_is_refused(self):
        self.r.locked("t-m09", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-m09")
        rc, line = self.r.review("t-m09", "engineering-code-review", eng_pass(self.r.base, ["src/app.txt"]),
                                 fp="0" * 64)
        self.assertIn("another tree", line)
        self.assertEqual(self.state("t-m09")[0], "NOT_VERIFIED")

    def test_m10_a_review_of_a_tree_changed_after_its_run_is_refused(self):
        self.r.locked("t-m10", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-m10")
        self.r.write("src/app.txt", "v3\n")
        rc, line = self.r.review("t-m10", "engineering-code-review", eng_pass(self.r.base, ["src/app.txt"]))
        self.assertIn("changed after run 1 passed", line)
        self.assertFalse(os.path.exists(os.path.join(self.r.gitdir(), "runs/t-m10/review-1.json")),
                         "no review is recorded for a tree no run passed on")

    def test_m11_a_review_after_a_failed_run_is_refused(self):
        self.r.locked("t-m11", [FAILING_ONCE])
        self.r.write("src/app.txt", "v2\n")
        self.r.write("flag.fail", "x\n")
        self.r.qc("run", "t-m11")
        rc, line = self.r.review("t-m11", "engineering-code-review",
                                 eng_pass(self.r.base, ["src/app.txt", "flag.fail"]))
        self.assertIn("no completed passing run", line)

    def test_m18_an_incomplete_review_is_not_verified(self):
        self.r.locked("t-m18", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-m18")
        text = eng_pass(self.r.base, ["src/app.txt"]).replace("complete: yes", "complete: no")
        self.r.review("t-m18", "engineering-code-review", text)
        st, line = self.state("t-m18")
        self.assertEqual(st, "NOT_VERIFIED", line)
        self.assertIn("incomplete", line)

    def test_m08_a_criterion_that_changes_the_tree_is_not_verified(self):
        writer = {"id": "ac-writes", "description": "writes into the tree",
                  "command": [PY, "-c", "open('src/new.txt','w').write('x')\n"
                                        "print('test result: ok. 3 passed; 0 failed')"]}
        self.r.locked("t-m08", [writer])
        rc, line = self.r.qc("run", "t-m08")
        self.assertIn("NOT_VERIFIED", line)
        self.assertIn("changed while the criteria ran", line)

    # Review text counts only inside its block

    def test_paths_and_fingerprint_outside_the_block_do_not_count(self):
        self.r.locked("t-m4", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-m4")
        text = eng_pass(self.r.base, ["src/other.txt"]) + "\nfiles: src/app.txt\n"
        rc, line = self.r.review("t-m4", "engineering-code-review", text)
        self.assertIn("does not name every changed path", line)
        fp = self.r.fingerprint()
        text = eng_pass(self.r.base, ["src/app.txt"]) + "\nqc_fingerprint: %s\n" % fp
        rc, line = self.r.qc("review-record", "t-m4", "engineering-code-review", stdin=text)
        self.assertIn("lacks the line qc_fingerprint", line)

    # Classification

    def test_other_agent_instruction_files_are_agent_control(self):
        self.r.locked("t-m8", [PASSING])
        for rel in ("CLAUDE.local.md", "docs/CLAUDE.md", "android/CLAUDE.md", ".pi/settings.json"):
            self.r.write(rel, "x\n")
        cls = self.paths("t-m8")
        for rel in ("CLAUDE.local.md", "docs/CLAUDE.md", "android/CLAUDE.md", ".pi/settings.json"):
            self.assertIn("AGENT_CONTROL", cls["paths"][rel], rel)

    def test_a_mocha_failure_behind_a_network_error_is_failed(self):
        crit = {"id": "ac-mocha", "description": "mocha with a failing test",
                "command": [PY, "-c", "import sys; print('getaddrinfo ENOTFOUND x\\n  3 passing\\n  1 failing');"
                                      "sys.exit(1)"]}
        self.r.locked("t-m11b", [crit])
        rc, line = self.r.qc("run", "t-m11b")
        self.assertIn("QC_STATE: FAILED", line)

    def test_the_trusted_build_directories_are_the_repositorys_own(self):
        if not os.path.exists(os.path.join(REPO, ".git")):
            self.skipTest("needs the repository checkout itself")
        p = subprocess.run([PY, "-B", os.path.join(REPO, ".claude/qc/qc.py"), "self-test"], cwd=REPO,
                           capture_output=True, text=True)
        self.assertEqual(json.loads(p.stdout)["untrusted_build_dirs"], [], p.stdout)


class HookRepairTest(unittest.TestCase):
    """The optional hooks while a loop is active: they do not fail open."""

    def setUp(self):
        self.parent = tempfile.mkdtemp(prefix="qc-parent-")
        self.r = Repo(parent=self.parent)
        self.r.locked("t-hook", [PASSING])
        self.r.write("src/app.txt", "v2\n")
        self.r.qc("run", "t-hook")
        self.r.qc("activate", "t-hook")

    def tearDown(self):
        shutil.rmtree(self.parent, ignore_errors=True)

    def hook(self, event, payload, cwd=None, env=None, isolated=True):
        argv = [PY, "-I", "-B"] if isolated else [PY]
        e = dict(self.r.env(), **(env or {}))
        p = subprocess.run([*argv, os.path.join(self.r.dir, ".claude/qc/hooks.py"), event],
                           cwd=cwd or self.r.dir, capture_output=True, text=True, input=json.dumps(payload), env=e)
        return p.returncode, p.stdout.strip(), p.stderr.strip()

    def stop_blocks(self, out):
        return json.loads(out or "{}").get("decision") == "block"

    def bash(self, cmd, **kw):
        rc, out, _ = self.hook("pre-tool", {"tool_name": "Bash", "tool_input": {"command": cmd}}, **kw)
        return json.loads(out or "{}").get("hookSpecificOutput", {}).get("permissionDecision")

    def test_a_cached_pyc_is_never_loaded(self):
        # A .pyc of a qc.py whose verdict always says VERIFIED, placed where `import qc` would use it.
        fake = os.path.join(self.parent, "fake_qc.py")
        with open(os.path.join(self.r.dir, ".claude/qc/qc.py")) as f:
            src = f.read()
        with open(fake, "w") as f:
            f.write(src + "\n\ndef verdict(root, sid):\n    return 'VERIFIED', 'fake'\n")
        cache = os.path.join(self.r.dir, ".claude/qc/__pycache__")
        os.makedirs(cache)
        tag = sys.implementation.cache_tag
        py_compile.compile(fake, cfile=os.path.join(cache, "qc.%s.pyc" % tag),
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        for isolated in (True, False):
            rc, out, _ = self.hook("stop", {"stop_hook_active": False,
                                            "last_assistant_message": "QC_STATE: VERIFIED | done"},
                                   isolated=isolated)
            self.assertTrue(self.stop_blocks(out), out)

    def test_a_cwd_outside_the_clone_still_finds_the_loop(self):
        outside = os.path.join(self.parent, "elsewhere")
        os.makedirs(outside)
        payload = {"tool_name": "Bash", "tool_input": {"command": "git commit -qm x"}, "cwd": outside}
        rc, out, _ = self.hook("pre-tool", payload, cwd=outside, env={"CLAUDE_PROJECT_DIR": self.r.dir})
        self.assertEqual(json.loads(out or "{}").get("hookSpecificOutput", {}).get("permissionDecision"), "deny")

    def test_an_unreadable_activation_fails_closed(self):
        with open(os.path.join(self.r.gitdir(), "active.json"), "w") as f:
            f.write("{not json")
        self.assertEqual(self.bash("git commit -qm x"), "deny")
        rc, out, _ = self.hook("stop", {"stop_hook_active": False,
                                        "last_assistant_message": "QC_STATE: VERIFIED | done"})
        self.assertTrue(self.stop_blocks(out), out)
        rc, out, err = self.hook("task-completed", {"task_subject": "[qc] t"})
        self.assertEqual(rc, 2, err)

    def test_a_guard_out_of_time_fails_closed(self):
        mod = types.ModuleType("hooks_under_test")
        path = os.path.join(self.r.dir, ".claude/qc/hooks.py")
        mod.__file__ = path
        with open(path) as f:
            exec(compile(f.read(), path, "exec"), mod.__dict__)
        mod.DEADLINE["stop"] = 1
        mod.qc.verdict = lambda root, sid: time.sleep(3) or ("VERIFIED", "a verdict that comes too late")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mod.main("stop", {"cwd": self.r.dir, "stop_hook_active": False,
                              "last_assistant_message": "QC_STATE: VERIFIED | done"})
        self.assertTrue(self.stop_blocks(buf.getvalue()), buf.getvalue())

    def test_owner_only_git_is_denied_whatever_precedes_the_subcommand(self):
        for cmd in ("git -P commit -qm x", "git --git-dir .git push", 'git -C "a b" push',
                    "git -c alias.ci=commit ci -m x", "git \\\ncommit -qm x", "env -i git push"):
            self.assertEqual(self.bash(cmd), "deny", cmd)
        for cmd in ("git -C . status", "git log --oneline", "git tag -l", "git merge-base HEAD HEAD",
                    "python3 .claude/qc/qc.py verdict t-hook"):
            self.assertIsNone(self.bash(cmd), cmd)

    def test_more_writes_to_the_control_plane_are_denied(self):
        for cmd in ("ln -sf /tmp/x .claude/qc/qc.py", "install -m 644 x .claude/qc/hooks.py",
                    "dd if=x of=CLAUDE.md", "find .claude/qc -name '*.py' -delete"):
            self.assertEqual(self.bash(cmd), "deny", cmd)
        rc, out, _ = self.hook("pre-tool", {"tool_name": "Write", "tool_input": {"file_path": "docs/CLAUDE.md"}})
        self.assertEqual(json.loads(out or "{}").get("hookSpecificOutput", {}).get("permissionDecision"), "deny")


if __name__ == "__main__":
    unittest.main()
