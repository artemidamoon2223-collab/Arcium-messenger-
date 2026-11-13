#!/usr/bin/env python3
"""Regression check for the SDK-license steps of two Android workflows (D-011).

The steps pipe `yes` into `sdkmanager --licenses`. Two failure modes matter:

- If sdkmanager fails, the step must fail. Before this fix both steps ended
  in `|| true`, which hid that.
- If sdkmanager succeeds, `yes` is still killed by SIGPIPE once sdkmanager
  stops reading (status 141). Under `pipefail` that alone fails a bare
  pipeline. The step must not fail because of it.

This script reads each step's real `run:` text from the workflow file, and
runs it with a fake `sdkmanager` the way GitHub Actions runs a step with no
`shell:` key: `bash -e <script>`. The android-two-device-e2e step sets
`set -euo pipefail` itself, so both shell modes are covered.

Fake sdkmanager modes (FAKE_SDK_MODE):
  read-then-ok    reads 4 bytes of stdin, exits 0  (yes gets SIGPIPE)
  ok-no-read      exits 0 without reading stdin    (yes gets SIGPIPE)
  read-then-fail  reads 4 bytes of stdin, exits 1
  fail-no-read    exits 3 without reading stdin
Every other sdkmanager call (`--install …`) exits 0.

Usage:
  python3 .github/scripts/test_sdk_license_steps.py            # this checkout
  python3 .github/scripts/test_sdk_license_steps.py --root DIR # another tree
Exit status 0 only if every case behaves as required.
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

STEPS = [
    (".github/workflows/android-ci.yml", "Accept Android SDK licenses"),
    (".github/workflows/android-two-device-e2e.yml", "Install the emulator and a system image"),
]

FAKE_SDKMANAGER = """#!/usr/bin/env bash
case " $* " in
  *" --licenses "*) ;;
  *) exit 0 ;;
esac
case "$FAKE_SDK_MODE" in
  read-then-ok)   head -c 4 >/dev/null; exit 0 ;;
  ok-no-read)     exit 0 ;;
  read-then-fail) head -c 4 >/dev/null; exit 1 ;;
  fail-no-read)   exit 3 ;;
  *) echo "unknown FAKE_SDK_MODE" >&2; exit 99 ;;
esac
"""

# mode -> must the step succeed?
EXPECTED = {
    "read-then-ok": True,
    "ok-no-read": True,
    "read-then-fail": False,
    "fail-no-read": False,
}


def step_script(root, workflow, name):
    doc = yaml.safe_load((root / workflow).read_text())
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            if step.get("name") == name:
                if "shell" in step or "defaults" in doc or "defaults" in job:
                    raise SystemExit(f"{workflow}: '{name}' sets its own shell; this check assumes `bash -e`")
                return step["run"]
    raise SystemExit(f"{workflow}: no step named '{name}'")


def yes_gets_sigpipe(sdk_root, mode):
    """Confirms, outside the step, that `yes` really dies of SIGPIPE in this mode."""
    probe = subprocess.run(
        ["bash", "-c", f'yes | "{sdk_root}/cmdline-tools/latest/bin/sdkmanager" --licenses; '
                       'echo "${PIPESTATUS[0]} ${PIPESTATUS[1]}"'],
        capture_output=True, text=True, env=dict(os.environ, FAKE_SDK_MODE=mode),
    )
    return probe.stdout.split()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    root = Path(p.parse_args().root)

    tmp = Path(tempfile.mkdtemp(prefix="fake-sdk-"))
    tool = tmp / "sdk/cmdline-tools/latest/bin/sdkmanager"
    tool.parent.mkdir(parents=True)
    tool.write_text(FAKE_SDKMANAGER)
    tool.chmod(0o755)
    sdk_root = tmp / "sdk"

    failures = 0
    print(f"tree: {root}")
    for mode in EXPECTED:
        print(f"probe {mode}: PIPESTATUS (yes sdkmanager) = {' '.join(yes_gets_sigpipe(sdk_root, mode))}")
    for workflow, name in STEPS:
        script = tmp / "step.sh"
        script.write_text(step_script(root, workflow, name))
        for mode, must_pass in EXPECTED.items():
            env = dict(os.environ, ANDROID_SDK_ROOT=str(sdk_root), FAKE_SDK_MODE=mode,
                       GITHUB_PATH=str(tmp / "github_path"), SYSTEM_IMAGE="system-images;fake")
            r = subprocess.run(["bash", "-e", str(script)], capture_output=True, text=True, env=env, timeout=60)
            ok = (r.returncode == 0) == must_pass
            failures += not ok
            print(f"  {'OK  ' if ok else 'FAIL'} {workflow} [{name}] sdkmanager={mode}: "
                  f"step exit {r.returncode}, required {'success' if must_pass else 'failure'}")
    print(f"SDK-LICENSE STEPS failures={failures}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
