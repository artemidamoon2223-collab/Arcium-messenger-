#!/usr/bin/env python3
"""Two people messaging through the app on two independent emulators.

Runs the steps of TwoDeviceMessengerTest with `am instrument`, one step per
run, on Alice's and Bob's emulators, in order or side by side as the scenario
needs, and passes each step what its user would have: the relay address and
the contact's card, fingerprint and name as read from the contact's own
screen. After every step the app is force-stopped and checked to be gone,
so every later step starts from a new app process (each step reports its
pid).

Bob's network is switched off and on around the offline step with airplane
mode; the switch is checked in Android's settings and connectivity state,
and the app on Bob's device must itself report having no network.

A step passes only if exactly one test ran and passed. Any failure, error,
ignored or assumption-failed test, crash or missing result fails the run.
Raw output of every step is kept in --out.

Usage: two_devices.py --alice SERIAL --bob SERIAL --relay HOST:PORT --out DIR
"""

import argparse
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path

APP = "com.arcium.messenger"
RUNNER = f"{APP}.test/androidx.test.runner.AndroidJUnitRunner"
CLASS = f"{APP}.e2e.TwoDeviceMessengerTest"
# Custom status code the test uses for data (TwoDeviceMessengerTest.DATA_CODE).
DATA_CODE = "42"
RESULT = {"0": "passed", "-1": "error", "-2": "failure", "-3": "ignored", "-4": "assumption failure"}


class Step:
    """One `am instrument` run of one test method on one device."""

    def __init__(self, out, serial, who, method, args):
        self.who, self.method = who, method
        self.started = time.time()
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
                    status = {}
        self.ready.set()

    def wait(self, timeout=900):
        self.proc.wait(timeout=timeout)
        self.reader.join(timeout=30)
        ok = self.results == [(self.method, "passed")] and any(
            l.startswith("INSTRUMENTATION_CODE: -1") for l in self.lines
        )
        took = time.time() - self.started
        print(f"  {self.who:5} {self.method}: {self.results or 'no result'} "
              f"(pid {self.data.get('pid', '?')}, {took:.0f} s) -> {'OK' if ok else 'FAILED'}")
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

    def peer_args(self, who):
        peer = "bob" if who == "alice" else "alice"
        args = {"relay": self.relay, "peerName": peer.capitalize()}
        if peer in self.cards:
            args["peerCard"], args["peerFingerprint"] = self.cards[peer]
        return args

    def start(self, who, method):
        return Step(self.out, self.serial[who], who, method, self.peer_args(who))

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

    def step(self, who, method):
        return self.finish(self.start(who, method))[0]

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
    r = Run(p.parse_args())

    for who in ("alice", "bob"):
        r.adb(who, "shell", "pm", "clear", APP)

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
    r.step("alice", "aliceSeesTheQueuedTextsDelivered")

    print("5. Bob's app restarts and the conversation goes on")
    r.together(("bob", "bobContinuesAfterRestart"), ("alice", "aliceAnswersAfterBobsRestart"))

    print("6. Alice loses the network while sending")
    r.together(("alice", "aliceSendsDuringAnOutage"), ("bob", "bobReceivesAfterAlicesOutage"))

    print("7. Keys on the relay that do not match a verified card are refused")
    r.step("alice", "aKeyMismatchOnTheRelayIsRefusedAndShown")

    print(r.summary())


if __name__ == "__main__":
    main()
