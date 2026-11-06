"""Refuse to touch anything but a verified Android emulator.

The end-to-end drivers clear app data, force-stop the app, switch airplane
mode and overwrite the app's files. Every one of those would destroy a real
user's data on a physical phone. Before the first such command, a driver
calls `require_emulators` with every serial it will touch; it returns only
if each one is verified, and otherwise exits non-zero having sent nothing
but the read-only queries below.

A target is verified only if all of these hold:
  1. its serial is the one adb gives an emulator, `emulator-<port>`;
  2. `adb -s SERIAL get-state` succeeds and says `device`;
  3. `getprop ro.kernel.qemu` or `getprop ro.boot.qemu` is exactly `1`;
  4. `getprop ro.hardware` is `ranchu` or `goldfish` (the emulator boards).

Any failed, timed-out or unexpected answer counts as "not verified".
"""

import re
import subprocess

EMULATOR_SERIAL = re.compile(r"emulator-\d+")
EMULATOR_HARDWARE = {"ranchu", "goldfish"}


def _read(serial, *command):
    """Runs one read-only adb query; returns its stripped stdout, or None on any failure."""
    try:
        r = subprocess.run(["adb", "-s", serial, *command], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip()


def why_not_emulator(serial):
    """None if `serial` is a verified emulator, else the reason it is not."""
    if not EMULATOR_SERIAL.fullmatch(serial or ""):
        return f"serial {serial!r} is not an emulator serial (emulator-<port>)"
    state = _read(serial, "get-state")
    if state != "device":
        return f"{serial}: adb get-state answered {state!r}, not 'device'"
    qemu = (_read(serial, "shell", "getprop", "ro.kernel.qemu"),
            _read(serial, "shell", "getprop", "ro.boot.qemu"))
    if "1" not in qemu:
        return f"{serial}: ro.kernel.qemu/ro.boot.qemu are {qemu!r}, not an emulator"
    hardware = _read(serial, "shell", "getprop", "ro.hardware")
    if hardware not in EMULATOR_HARDWARE:
        return f"{serial}: ro.hardware is {hardware!r}, not an emulator board"
    return None


def require_emulators(*serials):
    """Returns only if every serial is a verified emulator; otherwise exits non-zero."""
    problems = [p for p in (why_not_emulator(s) for s in serials) if p]
    if problems:
        raise SystemExit("refusing to touch any device: " + "; ".join(problems))
    print(f"targets verified as emulators: {', '.join(serials)}")
