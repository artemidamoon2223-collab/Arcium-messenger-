#!/usr/bin/env python3
"""D-007 through real app restarts on one emulator, driven from the host.

Each step is one `am instrument` run of one MasterKeyRestartTest method, so
each starts a new app process: `ArciumApp.onCreate` runs, then `MainActivity`.
After every step the app is force-stopped and checked to be gone. Between
steps the driver works on the app's own files from the host with `run-as`
(the debug APK is debuggable): it hashes `files/arcium.db` and
`files/master_key.blob`, deletes the blob, overwrites it with garbage, and
puts the original back.

Scenario:
  1. cleared app data; first launch creates an identity;
  2. restart with the key intact: the same identity, no onboarding;
  3. the blob is deleted: start-up must stop at the error screen, stay there
     across three retries, start no onboarding or messaging, write no blob,
     and leave the store's bytes unchanged;
  4. the blob is replaced with garbage: the same, and the garbage blob and
     the store must be left byte for byte as they were;
  5. the original blob is put back: the same identity opens again.

Every step runs even if an earlier one failed, so a run on unfixed code
records what each case does there; the exit status is non-zero if any check
failed. All output goes to stdout and --out.

Usage: master_key_restart.py --serial SERIAL --out DIR
"""

import argparse
import hashlib
import shlex
import subprocess
import sys
import time
from pathlib import Path

APP = "com.arcium.messenger"
RUNNER = f"{APP}.test/androidx.test.runner.AndroidJUnitRunner"
CLASS = f"{APP}.e2e.MasterKeyRestartTest"
DATA_CODE = "42"
RESULT = {"0": "passed", "-1": "error", "-2": "failure", "-3": "ignored", "-4": "assumption failure"}
DB = "files/arcium.db"
BLOB = "files/master_key.blob"
SAVED = "files/master_key.blob.d007-saved"
GARBAGE = "corrupted-master-key-blob-for-the-D-007-test"


class Driver:
    def __init__(self, serial, out):
        self.serial = serial
        self.out = Path(out)
        self.out.mkdir(parents=True, exist_ok=True)
        self.failures = []
        self.n = 0

    def adb(self, *command, check=True):
        return subprocess.run(["adb", "-s", self.serial, *command], capture_output=True, check=check)

    def shell(self, command, check=True):
        return self.adb("shell", command, check=check).stdout.decode(errors="replace").strip()

    def app_file(self, path):
        """The file's bytes, or None if it does not exist (read with run-as, binary-safe)."""
        exists = self.shell(f"run-as {APP} sh -c {shlex.quote(f'test -e {path} && echo yes || echo no')}")
        if exists != "yes":
            return None
        return self.adb("exec-out", "run-as", APP, "cat", path).stdout

    def digest(self, path):
        data = self.app_file(path)
        return "absent" if data is None else f"sha256:{hashlib.sha256(data).hexdigest()} ({len(data)} bytes)"

    def files(self):
        return self.shell(f"run-as {APP} ls -la files")

    def run_as(self, command):
        self.shell(f"run-as {APP} sh -c {shlex.quote(command)}")

    def stop_app(self):
        self.shell(f"am force-stop {APP}")
        deadline = time.time() + 30
        while self.shell(f"pidof {APP}", check=False):
            if time.time() > deadline:
                raise SystemExit("the app process is still running after force-stop")
            time.sleep(1)

    def check(self, ok, what):
        print(f"  check: {what} -> {'OK' if ok else 'FAILED'}")
        if not ok:
            self.failures.append(what)

    def step(self, method, **args):
        """Runs one test method in a new app process; returns (passed, data)."""
        self.n += 1
        extras = " ".join(f"-e {k} {shlex.quote(v)}" for k, v in args.items())
        command = f"am instrument -r -w -e class {CLASS}#{method} {extras} {RUNNER}"
        started = time.time()
        proc = subprocess.run(["adb", "-s", self.serial, "shell", command],
                              capture_output=True, text=True, timeout=600)
        log = self.out / f"{self.n:02d}-{method}.log"
        log.write_text(proc.stdout + proc.stderr)
        data, results, status, reports = {}, [], {}, []
        lines = proc.stdout.splitlines()
        for line in lines:
            if line.startswith("INSTRUMENTATION_STATUS: "):
                key, _, value = line[len("INSTRUMENTATION_STATUS: "):].partition("=")
                status[key] = value
            elif line.startswith("INSTRUMENTATION_STATUS_CODE: "):
                code = line.split(": ", 1)[1].strip()
                if code == DATA_CODE:
                    data.update(status)
                    reports.append(dict(status))
                elif code != "1":
                    results.append((status.get("test", "?"), RESULT.get(code, f"code {code}")))
                status = {}
        passed = results == [(method, "passed")] and any(l.startswith("INSTRUMENTATION_CODE: -1") for l in lines)
        crashed = any("shortMsg=Process crashed" in l or "INSTRUMENTATION_RESULT: shortMsg" in l for l in lines)
        print(f"  step {self.n}: {method}: {results or 'no result'}"
              f"{' (process crashed)' if crashed else ''} ({time.time() - started:.0f} s) -> "
              f"{'OK' if passed else 'FAILED'}")
        for r in reports:
            print(f"    reported: {r}")
        if not passed:
            for l in lines:
                if l.startswith(("INSTRUMENTATION_STATUS: stack=", "INSTRUMENTATION_RESULT", "java.lang.", "Caused by")):
                    print(f"    | {l[:400]}")
            self.failures.append(f"step {method}")
        self.stop_app()
        return passed, data


def main():
    sys.stdout.reconfigure(line_buffering=True)
    p = argparse.ArgumentParser()
    p.add_argument("--serial", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    d = Driver(a.serial, a.out)

    print("Device:", d.shell("getprop ro.build.fingerprint"), "| SDK", d.shell("getprop ro.build.version.sdk"))
    try:
        version = subprocess.run(["emulator", "-version"], capture_output=True, text=True, check=False)
        print("Emulator:", (version.stdout.splitlines() or ["unknown"])[0])
    except FileNotFoundError:
        print("Emulator: `emulator` is not on PATH; version unknown")

    d.shell(f"pm clear {APP}")
    d.stop_app()

    print("1. First launch creates an identity")
    _, data = d.step("firstLaunchCreatesAnIdentity")
    identity = data.get("identity", "")
    d.check(len(identity) == 64, f"an identity was created ({identity or 'none'})")
    print("  files:\n    " + d.files().replace("\n", "\n    "))
    print("  db:", d.digest(DB), "| blob:", d.digest(BLOB))

    print("2. Restart with the key intact")
    d.step("anIntactRestartOpensTheSameIdentity", expectedIdentity=identity)

    print("3. The blob is deleted; the store stays")
    d.run_as(f"cp {BLOB} {SAVED}")
    d.check(d.app_file(SAVED) == d.app_file(BLOB), "the original blob was saved aside")
    d.run_as(f"rm {BLOB}")
    db_before = d.digest(DB)
    print("  before: db", db_before, "| blob", d.digest(BLOB))
    d.step("aMissingKeyBlocksStartupAcrossRetries")
    print("  after:  db", d.digest(DB), "| blob", d.digest(BLOB))
    d.check(d.digest(BLOB) == "absent", "no replacement blob was written")
    d.check(d.digest(DB) == db_before, "the store is byte for byte unchanged")
    d.check(d.app_file("files/master_key.blob.tmp") is None, "no temporary blob was written")

    print("4. The blob is replaced with garbage; the store stays")
    d.run_as(f"printf %s {shlex.quote(GARBAGE)} > {BLOB}")
    db_before, blob_before = d.digest(DB), d.digest(BLOB)
    print("  before: db", db_before, "| blob", blob_before)
    d.step("aCorruptedKeyBlocksStartupAcrossRetries")
    print("  after:  db", d.digest(DB), "| blob", d.digest(BLOB))
    d.check(d.digest(BLOB) == blob_before, "the corrupted blob is byte for byte unchanged")
    d.check(d.digest(DB) == db_before, "the store is byte for byte unchanged")

    print("5. The original blob is put back")
    d.run_as(f"cp {SAVED} {BLOB}")
    d.step("anIntactRestartOpensTheSameIdentity", expectedIdentity=identity)

    print("  files:\n    " + d.files().replace("\n", "\n    "))
    line = f"MASTER-KEY RESTART steps={d.n} failures={len(d.failures)}"
    (d.out / "summary.txt").write_text(line + "\n" + "\n".join(d.failures) + "\n")
    print(line)
    for f in d.failures:
        print("  failed:", f)
    sys.exit(1 if d.failures else 0)


if __name__ == "__main__":
    main()
