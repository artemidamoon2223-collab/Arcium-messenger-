#!/usr/bin/env python3
"""Two people messaging through the app on two independent emulators.

Runs the steps of TwoDeviceMessengerTest with `am instrument`, one step per
run, on Alice's and Bob's emulators, in order or side by side as the scenario
needs, and passes each step what its user would have: the relay address and
the contact's card, fingerprint and name as read from the contact's own
screen. After every step the app is force-stopped (`am force-stop`) and
checked to be gone, so every later step starts from a new app process (each
step reports its pid). Two steps end with SIGKILL instead (the app process
signals itself, as `kill -9` would): once while a text is on the relay, once
while a text is recorded but not yet sent; the driver checks the process is
gone. Neither is a power loss.

A device's network is switched off and on around the offline steps with
airplane mode; the switch is checked in Android's settings and connectivity
state, and the app on that device must itself report having no network.

The envelopes the relay holds for Bob while he is offline are passed, as the
step reported them, to a later step that sends them to him again.

A step passes only if exactly one test ran and passed. Any failure, error,
ignored or assumption-failed test, crash or missing result fails the run.
Besides the SIGKILL steps, the other exception is a negative control run in
place: it passes only if its test ran and failed with an assertion whose
first line matches the expected pattern exactly. Raw output of every step is
kept in --out; what a step reports, apart from cards and envelopes, is
printed with its result.

Usage: two_devices.py --alice SERIAL --bob SERIAL --relay HOST:PORT --out DIR
"""

import argparse
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path

from emulator_guard import require_emulators

APP = "com.arcium.messenger"
RUNNER = f"{APP}.test/androidx.test.runner.AndroidJUnitRunner"
CLASS = f"{APP}.e2e.TwoDeviceMessengerTest"
# Custom status code the test uses for data (TwoDeviceMessengerTest.DATA_CODE).
DATA_CODE = "42"
RESULT = {"0": "passed", "-1": "error", "-2": "failure", "-3": "ignored", "-4": "assumption failure"}
# Reported data not worth printing: the pid is printed anyway, the rest is long.
UNPRINTED = {"pid", "card", "fingerprint", "replay", "replayTo", "ready", "killing"}


class Step:
    """One `am instrument` run of one test method on one device."""

    def __init__(self, out, serial, who, method, args):
        self.who, self.method = who, method
        self.started = time.time()
        # Set for a step whose process the driver kills: it passes only if
        # the process died before the test could finish.
        self.expect_kill = False
        # Set for a negative control: it passes only if the test failed with
        # an assertion whose first line matches this pattern exactly.
        self.expect_failure = None
        self.failures = []
        self.log = out / f"{len(list(out.glob('*.log'))):02d}-{who}-{method}.log"
        self.data, self.results, self.lines = {}, [], []
        self.ready = threading.Event()
        extras = " ".join(f"-e {k} {shlex.quote(v)}" for k, v in args.items())
        command = f"am instrument -r -w -e class {CLASS}#{method} {extras} {RUNNER}"
        self.proc = subprocess.Popen(
            ["adb", "-s", serial, "shell", command],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        status = {}
        with self.log.open("w") as log:
            for line in self.proc.stdout:
                log.write(line)
                log.flush()
                line = line.rstrip("\r\n")
                self.lines.append(line)
                if line.startswith("INSTRUMENTATION_STATUS: "):
                    key, _, value = line[len("INSTRUMENTATION_STATUS: "):].partition("=")
                    status[key] = value
                elif line.startswith("INSTRUMENTATION_STATUS_CODE: "):
                    code = line.split(": ", 1)[1].strip()
                    if code == DATA_CODE:
                        self.data.update(status)
                        if "ready" in status:
                            self.ready.set()
                    elif code != "1":
                        self.results.append((status.get("test", "?"), RESULT.get(code, f"code {code}")))
                        if code in ("-1", "-2"):
                            # The first line of the stack: the exception and its message.
                            self.failures.append(status.get("stack", ""))
                    status = {}
        self.ready.set()

    def wait(self, timeout=900):
        self.proc.wait(timeout=timeout)
        self.reader.join(timeout=30)
        if self.expect_kill:
            ok = ("killing" in self.data and not self.results
                  and any("shortMsg=Process crashed" in l for l in self.lines))
        elif self.expect_failure is not None:
            ok = (self.results == [(self.method, "failure")]
                  and any(re.fullmatch(self.expect_failure, f) for f in self.failures)
                  and any(l.startswith("INSTRUMENTATION_CODE: -1") for l in self.lines))
        else:
            ok = self.results == [(self.method, "passed")] and any(
                l.startswith("INSTRUMENTATION_CODE: -1") for l in self.lines
            )
        took = time.time() - self.started
        print(f"  {self.who:5} {self.method}: {self.results or 'no result'} "
              f"(pid {self.data.get('pid', '?')}, {took:.0f} s) -> {'OK' if ok else 'FAILED'}")
        for k, v in self.data.items():
            if k not in UNPRINTED:
                print(f"    {k}: {v[:400]}")
        if self.expect_failure is not None:
            for f in self.failures:
                print(f"    expected failure: {f[:400]}")
        if not ok:
            print("\n".join("    | " + l for l in self.lines[-60:]))
        return ok


class Run:
    def __init__(self, a):
        self.out = Path(a.out)
        self.out.mkdir(parents=True, exist_ok=True)
        self.serial = {"alice": a.alice, "bob": a.bob}
        self.relay = a.relay
        self.cards = {}
        self.last_pid = {}
        self.passed = self.failed = 0

    def adb(self, who, *command, check=True):
        return subprocess.run(["adb", "-s", self.serial[who], *command],
                              capture_output=True, text=True, check=check)

    def stop_app(self, who):
        """Kills the app as a user swiping it away would, and checks it is gone."""
        self.adb(who, "shell", "am", "force-stop", APP)
        if self.adb(who, "shell", "pidof", APP, check=False).stdout.strip():
            raise SystemExit(f"{who}: the app process is still running after force-stop")

    def gone(self, who, pid):
        """Checks the process `pid` no longer exists."""
        deadline = time.time() + 30
        while pid in self.adb(who, "shell", "pidof", APP, check=False).stdout.split():
            if time.time() > deadline:
                raise SystemExit(f"{who}: pid {pid} survived SIGKILL")
            time.sleep(1)
        print(f"  {who}: pid {pid} ended by SIGKILL")

    def peer_args(self, who):
        peer = "bob" if who == "alice" else "alice"
        args = {"relay": self.relay, "peerName": peer.capitalize()}
        if peer in self.cards:
            args["peerCard"], args["peerFingerprint"] = self.cards[peer]
        return args

    def start(self, who, method, extra=None):
        return Step(self.out, self.serial[who], who, method, {**self.peer_args(who), **(extra or {})})

    def finish(self, *steps):
        results = [s.wait() for s in steps]
        for s in steps:
            self.stop_app(s.who)
            pid = s.data.get("pid")
            if pid is None or pid == self.last_pid.get(s.who):
                raise SystemExit(f"{s.who}: {s.method} did not report a new app process (pid {pid})")
            self.last_pid[s.who] = pid
        self.passed += sum(results)
        self.failed += len(results) - sum(results)
        if not all(results):
            raise SystemExit(self.summary())
        return steps

    def step(self, who, method, extra=None):
        return self.finish(self.start(who, method, extra))[0]

    def expect_failing(self, who, method, extra, pattern):
        """A negative control: passes only if the test fails with an assertion matching `pattern`."""
        s = self.start(who, method, extra)
        s.expect_failure = pattern
        return self.finish(s)[0]

    def killed(self, who, method):
        """A step that ends with SIGKILL: passes only if its process died before the test finished."""
        s = self.start(who, method)
        s.expect_kill = True
        s.proc.wait(timeout=300)
        s.reader.join(timeout=30)
        if "killing" in s.data:
            self.gone(who, s.data["pid"])
        self.finish(s)

    def together(self, *pairs):
        return self.finish(*[self.start(who, method) for who, method in pairs])

    def network(self, who, on):
        """Airplane mode off (on=True) or on, then waits until Android reports it."""
        self.adb(who, "shell", "cmd", "connectivity", "airplane-mode", "disable" if on else "enable")
        want = "0" if on else "1"
        deadline = time.time() + 60
        while time.time() < deadline:
            state = self.adb(who, "shell", "settings", "get", "global", "airplane_mode_on").stdout.strip()
            active = "Active default network: none" not in self.adb(who, "shell", "dumpsys", "connectivity").stdout
            if state == want and active == on:
                print(f"  {who}: network {'on' if on else 'off'} (airplane_mode_on={state})")
                return
            time.sleep(2)
        raise SystemExit(f"{who}: network did not turn {'on' if on else 'off'}")

    def summary(self):
        line = f"E2E steps={self.passed + self.failed} passed={self.passed} failed={self.failed}"
        (self.out / "summary.txt").write_text(line + "\n")
        return line


def main():
    sys.stdout.reconfigure(line_buffering=True)
    p = argparse.ArgumentParser()
    p.add_argument("--alice", required=True)
    p.add_argument("--bob", required=True)
    p.add_argument("--relay", required=True, help="the relay as the emulators reach it")
    p.add_argument("--out", required=True)
    args = p.parse_args()
    # The fake-adb regression check of the target guard runs first, with no
    # device involved; then both targets are verified before either is touched.
    if os.environ.get("ARCIUM_E2E_GUARD_SELFTEST") != "running":
        selftest = Path(__file__).with_name("test_emulator_guard.py")
        if subprocess.run([sys.executable, str(selftest)]).returncode != 0:
            raise SystemExit("the emulator-guard regression check failed; no device was touched")
    require_emulators(args.alice, args.bob)
    r = Run(args)

    for who in ("alice", "bob"):
        r.adb(who, "shell", "pm", "clear", APP)

    # First, so that no app process runs after the final step: it needs only
    # the relay, and a mailbox of its own.
    print("0. The final checks fail on fixtures that break what they guard")
    r.step("alice", "theFinalChecksRejectViolatedFixtures")

    print("1. Both create an identity, set the relay and show their card")
    for s in r.together(("alice", "onboard"), ("bob", "onboard")):
        r.cards[s.who] = (s.data["card"], s.data["fingerprint"])
    if r.cards["alice"][0] == r.cards["bob"][0]:
        raise SystemExit("both devices show the same card")

    print("2. Each adds the other after comparing fingerprints; an impostor card is refused")
    r.together(("alice", "addContact"), ("bob", "addContact"))

    print("3. Alice writes, Bob reads and answers")
    r.together(("alice", "aliceSendsHello"), ("bob", "bobRepliesToHello"))

    print("4. Bob goes offline; Alice writes; Bob comes back and catches up")
    r.network("bob", on=False)
    bob = r.start("bob", "bobIsOfflineThenCatchesUp")
    if not bob.ready.wait(timeout=300) or "ready" not in bob.data:
        r.finish(bob)
    alice = r.start("alice", "aliceSendsWhileBobIsOffline")
    try:
        r.finish(alice)
    finally:
        r.network("bob", on=True)
    r.finish(bob)
    replay = {k: alice.data[k] for k in ("replayTo", "replay", "replayHeldMaxSeq") if k in alice.data}
    if len(replay) != 3:
        raise SystemExit("alice: aliceSendsWhileBobIsOffline did not report the envelopes held for Bob")
    r.step("alice", "aliceSeesTheQueuedTextsDelivered")

    print("5. Bob's app restarts and the conversation goes on")
    r.together(("bob", "bobContinuesAfterRestart"), ("alice", "aliceAnswersAfterBobsRestart"))

    print("6. Alice's process is killed with SIGKILL while her text is on its way")
    r.killed("alice", "aliceIsKilledWithATextInFlight")
    r.together(("alice", "aliceSeesTheTextFromBeforeTheKillDelivered"),
               ("bob", "bobReceivesTheTextFromBeforeTheKill"))

    print("7. Alice loses the network while sending")
    r.together(("alice", "aliceSendsDuringAnOutage"), ("bob", "bobReceivesAfterAlicesOutage"))

    print("8. Keys on the relay that do not match a verified card are refused")
    r.step("alice", "aKeyMismatchOnTheRelayIsRefusedAndShown")

    print("9. Alice's process is killed with SIGKILL before her text reaches the relay")
    r.network("alice", on=False)
    try:
        r.killed("alice", "aliceIsKilledBeforePublishing")
    finally:
        r.network("alice", on=True)
    r.together(("alice", "aliceDeliversTheTextFromBeforePublishing"),
               ("bob", "bobReceivesTheTextFromBeforePublishing"))

    print("10. Bob's app restarts while he is offline, then catches up")
    r.network("bob", on=False)
    try:
        r.step("alice", "aliceWritesWhileBobRestartsOffline")
        r.step("bob", "bobOpensTheChatOffline")
    finally:
        r.network("bob", on=True)
    r.step("bob", "bobCatchesUpAfterRestartingOffline")

    print("11. The relay delivers envelopes Bob accepted long ago a second time")
    r.step("bob", "bobIgnoresReplayedEnvelopes", replay)

    print("12. Final state, one device at a time: nothing pending for the contact, nothing")
    print("    left on the relay, every text in each history once")
    final = "everyTextIsInTheHistoryOnceAfterRepeatedSyncs"
    # Negative control in place, in the order of run 82: Bob, then Alice. Alice's
    # new process sends Bob once more the text still waiting for his receipt
    # (it is on the relay before she fetches the receipt), after Bob's pass.
    # Her check of his mailbox must find exactly that one envelope and fail.
    r.step("bob", final)
    r.expect_failing("alice", final, {"checkPeerMailbox": "1"},
                     r"java\.lang\.AssertionError: left on the relay for Bob: \[seq=\d+ len=\d+\]")
    # Bob takes it, a duplicate, and answers with a new receipt; Alice's last
    # pass takes that, sends nothing, and finds both mailboxes empty. Each
    # device's last pass also shows it has nothing pending and nothing left to
    # process, and no app process runs after Alice's.
    r.step("bob", final)
    r.step("alice", final, {"checkPeerMailbox": "1"})

    print(r.summary())

    print("13. D-007: master-key loss and corruption across real restarts, on Alice's emulator")
    restart = subprocess.run([sys.executable, str(Path(__file__).with_name("master_key_restart.py")),
                              "--serial", r.serial["alice"], "--out", str(r.out / "master-key-restart")])
    if restart.returncode != 0:
        raise SystemExit("the D-007 restart scenario failed (see master-key-restart in --out)")


if __name__ == "__main__":
    main()
