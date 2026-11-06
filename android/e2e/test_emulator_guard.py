#!/usr/bin/env python3
"""Regression check: the e2e drivers touch only verified emulators.

Runs `master_key_restart.py` and `two_devices.py` against a fake `adb` (put
first on PATH) that logs every command it receives and answers as one of:

  emulator  - serial emulator-<port>, state device, ro.kernel.qemu=1,
              ro.hardware=ranchu; also keeps a small in-memory app file
              system, so the master-key scenario can run end to end;
  physical  - state device, qemu props empty, ro.hardware=qcom;
  unknown   - adb get-state fails (offline, unauthorized, absent);
  noprops   - state device, but every getprop fails.

A physical, unknown or unverifiable target must make the driver exit
non-zero having sent only read-only queries (get-state, getprop) to any
device: no pm clear, am force-stop, am instrument, run-as, settings or
airplane-mode command on either target. A verified emulator must still
work: the master-key scenario runs to the end against it, and the
two-device driver goes on to clear both targets.

No real device is used. `two_devices.py` runs this file before it touches
any device; run it alone with `python3 android/e2e/test_emulator_guard.py`.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
READ_ONLY = ("get-state", "shell getprop ")

FAKE_ADB = textwrap.dedent(r'''
    #!/usr/bin/env python3
    import json, os, re, shlex, sys
    profiles = json.loads(os.environ["FAKE_ADB_PROFILES"])
    state_file = os.environ["FAKE_ADB_STATE"]
    args = sys.argv[1:]
    serial = None
    if args[:1] == ["-s"]:
        serial, args = args[1], args[2:]
    with open(os.environ["FAKE_ADB_LOG"], "a") as log:
        log.write(json.dumps({"serial": serial, "args": args}) + "\n")
    profile = profiles.get(serial, "unknown")
    if args == ["get-state"]:
        if profile == "unknown":
            sys.stderr.write("error: device offline\n"); sys.exit(1)
        print("device"); sys.exit(0)
    # Profiles of the form "<prop>:fail" or "<prop>:hang" answer like a
    # verified emulator except for that one property query, which exits
    # non-zero or never returns. "emulator-boot" sets only ro.boot.qemu=1
    # (ro.kernel.qemu answers successfully, but empty).
    import time
    broken, _, mode = profile.partition(":")
    def getprop(name):
        if profile == "noprops":
            sys.exit(1)
        if mode and name == broken:
            if mode == "fail":
                sys.exit(1)
            time.sleep(60); sys.exit(0)
        emu = profile in ("emulator", "emulator-boot") or bool(mode)
        values = {"ro.kernel.qemu": "1" if emu and profile != "emulator-boot" else "",
                  "ro.boot.qemu": "1" if profile == "emulator-boot" else "",
                  "ro.hardware": "ranchu" if emu else "qcom",
                  "ro.build.fingerprint": "fake/" + profile, "ro.build.version.sdk": "30"}
        print(values.get(name, ""))
        sys.exit(0)
    if args[:2] == ["shell", "getprop"]:
        getprop(args[2])
    if args[:1] == ["shell"] and len(args) == 2 and args[1].startswith("getprop "):
        getprop(args[1].split()[1])
    # Beyond this point: only an emulator profile is expected to be asked anything.
    files = json.load(open(state_file)) if os.path.exists(state_file) else {}
    def save():
        json.dump(files, open(state_file, "w"))
    cmd = " ".join(args[1:]) if args[:1] == ["shell"] else " ".join(args)
    if args[:1] == ["exec-out"]:
        sys.stdout.write(files.get(args[-1], "")); sys.exit(0)
    if cmd.startswith("pidof"):
        sys.exit(1)
    if cmd.startswith("pm clear"):
        files.clear(); save(); print("Success"); sys.exit(0)
    if "am instrument" in cmd:
        method = re.search(r"#(\w+)", cmd).group(1)
        data = {"pid": str(os.getpid())}
        if method == "firstLaunchCreatesAnIdentity":
            files["files/arcium.db"] = "db"; files["files/master_key.blob"] = "blob"; save()
            data["identity"] = "ab" * 32
        if method == "anIntactRestartOpensTheSameIdentity":
            data["identity"] = "ab" * 32
        for k, v in data.items():
            print(f"INSTRUMENTATION_STATUS: {k}={v}")
        print("INSTRUMENTATION_STATUS_CODE: 42")
        print(f"INSTRUMENTATION_STATUS: test={method}\nINSTRUMENTATION_STATUS_CODE: 1")
        print(f"INSTRUMENTATION_STATUS: test={method}\nINSTRUMENTATION_STATUS_CODE: 0")
        print("INSTRUMENTATION_RESULT: stream=OK\nINSTRUMENTATION_CODE: -1")
        sys.exit(0)
    m = re.match(r"run-as \S+ sh -c (.*)", cmd)
    if m:
        script = shlex.split(m.group(1))[0]
        for part in script.split("&&"):
            part = part.strip()
            t = re.match(r"test -e (\S+)", part)
            if t:
                print("yes" if t.group(1) in files else "no"); break
            c = re.match(r"cp (\S+) (\S+)$", part)
            if c: files[c.group(2)] = files[c.group(1)]
            r = re.match(r"rm (\S+)$", part)
            if r: files.pop(r.group(1), None)
            w = re.match(r"printf %s (\S+) > (\S+)$", part)
            if w: files[w.group(2)] = w.group(1)
        save(); sys.exit(0)
    if cmd.startswith("run-as") and cmd.endswith("ls -la files"):
        print("\n".join(sorted(files))); sys.exit(0)
    sys.exit(0)
''').lstrip()


class Harness:
    def __init__(self, profiles):
        self.dir = Path(tempfile.mkdtemp(prefix="fake-adb-"))
        adb = self.dir / "adb"
        adb.write_text(FAKE_ADB)
        adb.chmod(0o755)
        self.log = self.dir / "log.jsonl"
        self.env = dict(os.environ,
                        PATH=f"{self.dir}{os.pathsep}{os.environ.get('PATH', '')}",
                        FAKE_ADB_PROFILES=json.dumps(profiles),
                        FAKE_ADB_STATE=str(self.dir / "files.json"),
                        FAKE_ADB_LOG=str(self.log),
                        ARCIUM_E2E_ADB_TIMEOUT="2",
                        ARCIUM_E2E_GUARD_SELFTEST="running")

    def run(self, script, *args):
        return subprocess.run([sys.executable, str(HERE / script), *args, "--out", str(self.dir / "out")],
                              env=self.env, capture_output=True, text=True, timeout=120)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text().splitlines()]

    def mutations(self):
        """Every command that is not a read-only identity query."""
        return [c for c in self.calls() if not " ".join(c["args"]).startswith(READ_ONLY)]


class GuardTest(unittest.TestCase):

    def assertRefusedUntouched(self, harness, result):
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("refusing to touch any device", result.stdout + result.stderr)
        self.assertEqual([], harness.mutations(), "no command beyond get-state/getprop may reach any device")

    def test_restart_driver_refuses_a_physical_device(self):
        h = Harness({"emulator-5554": "physical"})
        self.assertRefusedUntouched(h, h.run("master_key_restart.py", "--serial", "emulator-5554"))

    def test_restart_driver_refuses_a_non_emulator_serial_even_with_emulator_props(self):
        h = Harness({"R58M123ABC": "emulator"})
        r = h.run("master_key_restart.py", "--serial", "R58M123ABC")
        self.assertRefusedUntouched(h, r)
        self.assertEqual([], h.calls(), "a non-emulator serial must not even be queried")

    def test_restart_driver_refuses_an_unknown_or_unverifiable_target(self):
        for profile in ("unknown", "noprops"):
            with self.subTest(profile=profile):
                h = Harness({"emulator-5554": profile})
                self.assertRefusedUntouched(h, h.run("master_key_restart.py", "--serial", "emulator-5554"))

    def test_restart_driver_runs_the_whole_scenario_on_a_verified_emulator(self):
        h = Harness({"emulator-5554": "emulator"})
        r = h.run("master_key_restart.py", "--serial", "emulator-5554")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("MASTER-KEY RESTART steps=5 failures=0", r.stdout)
        args = [" ".join(c["args"]) for c in h.calls()]
        self.assertTrue(any("pm clear" in a for a in args))
        first_mutation = next(i for i, a in enumerate(args) if not a.startswith(READ_ONLY))
        self.assertTrue(any(a == "get-state" for a in args[:first_mutation]), "verification comes first")

    # A query that fails or hangs refuses the target even when the other
    # QEMU property already answered "1" (the gap in 8a20d66: the failed
    # answer was read as "not set" and the other "1" was accepted).
    PARTIAL = ("ro.boot.qemu:fail", "ro.boot.qemu:hang", "ro.kernel.qemu:fail", "ro.kernel.qemu:hang",
               "ro.hardware:fail", "ro.hardware:hang")

    def test_restart_driver_refuses_a_partially_failing_or_hanging_query(self):
        for profile in self.PARTIAL:
            with self.subTest(profile=profile):
                h = Harness({"emulator-5554": profile})
                self.assertRefusedUntouched(h, h.run("master_key_restart.py", "--serial", "emulator-5554"))

    def test_two_device_driver_refuses_a_partially_failing_or_hanging_query_on_either_target(self):
        for profile in self.PARTIAL:
            for alice, bob in ((profile, "emulator"), ("emulator", profile)):
                with self.subTest(alice=alice, bob=bob):
                    h = Harness({"emulator-5554": alice, "emulator-5556": bob})
                    r = h.run("two_devices.py", "--alice", "emulator-5554", "--bob", "emulator-5556",
                              "--relay", "10.0.2.2:7700")
                    self.assertRefusedUntouched(h, r)

    def test_an_emulator_that_sets_only_ro_boot_qemu_is_accepted(self):
        # ro.kernel.qemu answers successfully but empty: not a failure.
        h = Harness({"emulator-5554": "emulator-boot"})
        r = h.run("master_key_restart.py", "--serial", "emulator-5554")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)
        self.assertIn("targets verified as emulators: emulator-5554", r.stdout)

    def test_two_device_driver_touches_neither_target_if_one_is_not_verified(self):
        for alice, bob in (("emulator", "physical"), ("physical", "emulator"),
                           ("emulator", "unknown"), ("noprops", "emulator")):
            with self.subTest(alice=alice, bob=bob):
                h = Harness({"emulator-5554": alice, "emulator-5556": bob})
                r = h.run("two_devices.py", "--alice", "emulator-5554", "--bob", "emulator-5556",
                          "--relay", "10.0.2.2:7700")
                self.assertRefusedUntouched(h, r)

    def test_two_device_driver_refuses_a_non_emulator_serial(self):
        h = Harness({"emulator-5554": "emulator", "0123456789ABCDEF": "emulator"})
        r = h.run("two_devices.py", "--alice", "emulator-5554", "--bob", "0123456789ABCDEF",
                  "--relay", "10.0.2.2:7700")
        self.assertRefusedUntouched(h, r)

    def test_two_device_driver_proceeds_on_two_verified_emulators(self):
        h = Harness({"emulator-5554": "emulator", "emulator-5556": "emulator"})
        r = h.run("two_devices.py", "--alice", "emulator-5554", "--bob", "emulator-5556",
                  "--relay", "10.0.2.2:7700")
        out = r.stdout + r.stderr
        self.assertIn("targets verified as emulators: emulator-5554, emulator-5556", out)
        cleared = {c["serial"] for c in h.calls() if c["args"][:3] == ["shell", "pm", "clear"]}
        # The fake adb cannot play the messaging scenario, so the run stops
        # after the first step; what matters here is that it got that far.
        self.assertEqual({"emulator-5554", "emulator-5556"}, cleared, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
