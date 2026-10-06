#!/usr/bin/env python3
"""Check that the arcium-test job publishes only sanitised localnet diagnostics.

Usage: check_diagnostics_gate.py              check .github/workflows/arcium-ci.yml
       check_diagnostics_gate.py --self-test  also run that job's scripts on fixtures

The structural check reads the arcium-test job and requires that:
  - its only upload step uploads ${{ runner.temp }}/localnet-publish, and only
    if the `diagnostics_gate` step succeeded;
  - that gate step comes immediately before the upload, runs even after a
    failure, and runs `scrub_localnet_diagnostics.py verify` on that directory;
  - nothing but the scrubber's `publish` command writes to the publication
    directory (the test step may only create it empty), and every other step
    that reads it runs only if the gate succeeded.

The self-test runs the job's own test, gate and summary scripts with fake
`arcium`, `docker` and `sudo` commands and synthetic keys, then decides what
the upload step would publish: the publication directory if the gate passed,
nothing otherwise. It also checks that mutated workflows (unconditional
upload, raw directory uploaded, a step between gate and upload, a copy into
the publication directory, an ungated summary) are rejected.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/arcium-ci.yml"
PUBLISH = "${{ runner.temp }}/localnet-publish"
GATE_ID = "diagnostics_gate"
GATED = f"always() && steps.{GATE_ID}.outcome == 'success'"
VERIFY = 'scrub_localnet_diagnostics.py verify "$LOCALNET_PUBLISH_DIR"'
TEST_STEP = "arcium test, one fresh localnet per MPC scenario"
# The only lines of the test step allowed to name the publication directory.
ALLOWED_PUBLISH_LINES = {
    'rm -rf "$LOCALNET_RAW_DIR" "$LOCALNET_STAGING_DIR" "$LOCALNET_PUBLISH_DIR"',
    'mkdir -p "$LOCALNET_RAW_DIR" "$LOCALNET_PUBLISH_DIR"',
    '"$raw" "$LOCALNET_PUBLISH_DIR/$scenario" "$LOCALNET_STAGING_DIR" \\',
}


def job_steps(text, job="arcium-test"):
    """The steps of `job` as dicts of name/id/if/uses/shell/working-directory,
    env and with (dicts) and run (dedented text). Only the layout this
    workflow uses is understood."""
    lines = text.splitlines()
    try:
        start = lines.index(f"  {job}:")
    except ValueError:
        raise SystemExit(f"job {job} not found")
    body = []
    for line in lines[start + 1:]:
        if re.match(r"^  \S", line):
            break
        body.append(line)
    steps, step, block, run = [], None, None, None
    for line in body:
        if line.startswith("      - "):
            step = {"env": {}, "with": {}}
            steps.append(step)
            line = "        " + line[8:]
            block = run = None
        if step is None:
            continue
        if run is not None:
            if line.strip() == "" or line.startswith("          "):
                run.append(line[10:])
                continue
            step["run"] = "\n".join(run).rstrip("\n") + "\n"
            run = None
        m = re.match(r"^        ([\w-]+):\s*(.*)$", line)
        if m:
            key, value = m.groups()
            block = None
            if key in ("env", "with") and value == "":
                block = key
            elif key == "run" and value == "|":
                run = []
            else:
                step[key] = value.strip()
            continue
        m = re.match(r"^          ([\w-]+):\s*(.*)$", line)
        if m and block:
            step[block][m.group(1)] = m.group(2).strip()
    if run is not None:
        step["run"] = "\n".join(run).rstrip("\n") + "\n"
    return steps


def check_workflow(text):
    errors = []
    steps = job_steps(text)
    uploads = [i for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/upload-artifact@")]
    if len(uploads) != 1:
        return [f"expected exactly one upload step in arcium-test, found {len(uploads)}"]
    u = uploads[0]
    up = steps[u]
    if up.get("if") != GATED:
        errors.append(f"upload must run only if the gate passed (if: {GATED}), has: {up.get('if')}")
    if up["with"].get("path") != PUBLISH:
        errors.append(f"upload must upload only {PUBLISH}, uploads: {up['with'].get('path')}")
    gate = steps[u - 1] if u > 0 else {}
    if gate.get("id") != GATE_ID:
        errors.append(f"the step right before the upload must be the {GATE_ID} step")
    else:
        if gate.get("if") != "always()":
            errors.append("the gate must run even after a failure (if: always())")
        if VERIFY not in gate.get("run", ""):
            errors.append(f"the gate must run {VERIFY}")
        if gate["env"].get("LOCALNET_PUBLISH_DIR") != PUBLISH:
            errors.append(f"the gate must check {PUBLISH}")
    tests = [s for s in steps if s.get("name") == TEST_STEP]
    if len(tests) != 1:
        errors.append(f"test step not found: {TEST_STEP}")
    else:
        t = tests[0]
        if t["env"].get("LOCALNET_PUBLISH_DIR") != PUBLISH:
            errors.append(f"the test step must publish to {PUBLISH}")
        run = t.get("run", "")
        for line in run.splitlines():
            if "LOCALNET_PUBLISH_DIR" in line and line.strip() not in ALLOWED_PUBLISH_LINES:
                errors.append(f"only the scrubber may write to the publication directory: {line.strip()}")
        if "scrub_localnet_diagnostics.py publish" not in run:
            errors.append("the test step must publish through scrub_localnet_diagnostics.py publish")
    for s in steps:
        if s is up or s is gate or (tests and s is tests[0]):
            continue
        mentions = "localnet-publish" in str(s) or "LOCALNET_PUBLISH_DIR" in str(s)
        if mentions and s.get("if") != GATED:
            errors.append(f"step reads the publication directory without the gate: {s.get('name')}")
    return errors


# ---------------------------------------------------------------- self-test

FAKE_ARCIUM = r'''#!/usr/bin/env bash
set -e
[ "$1" = test ] || exit 2
s=$LOCALNET_MPC_SCENARIO
title=$(grep "^$s " "$FAKE_TITLES" | cut -d' ' -f2-)
mkdir -p artifacts/localnet artifacts/arx_node_logs .anchor/test-ledger
if [ "$FAKE_NO_KEYS" != "$s" ]; then
  python3 -c 'import json, os; print(json.dumps(list(os.urandom(64))))' > artifacts/localnet/node_0.json
fi
if [ "$FAKE_BROKEN_KEY" = "$s" ]; then ln -s /nonexistent/key artifacts/localnet/node_1.json; fi
echo "node log for $s" > "artifacts/arx_node_logs/arx_log_05_10_2026_10:00:00_$s.log"
echo "validator log for $s" > .anchor/test-ledger/validator.log
cat > "$LOCALNET_DIAG_DIR/computation-$s.json" <<JSON
{"computationAccount": "Acc$s", "computationOffset": "1", "submitSignature": "sig", "submitSlot": 5,
 "startedAt": "t", "msSincePreviousFinalization": null, "outcome": "finalized", "waitedMs": 2000,
 "observations": [{"ms": 0, "slot": 5, "status": "queued", "inMempool": false, "inExecpool": true}],
 "transactions": [{"signature": "sig", "slot": 5, "err": null}]}
JSON
if [ "$FAKE_LEAK" = "$s" ]; then
  python3 -c "
import json, sys
sys.path.insert(0, '$FAKE_SCRIPTS')
from scrub_localnet_diagnostics import b58
kp = json.load(open('artifacts/localnet/node_0.json'))
print('leaked', b58(bytes(kp[:32])))" > artifacts/arx_node_logs/leak.log
fi
if [ "$FAKE_HANG" = "$s" ]; then sleep 600; fi
if [ "$FAKE_FAIL" = "$s" ]; then printf '  5 passing (1s)\n  1 failing\n'; exit 1; fi
printf '    \xe2\x9c\x94 %s (1ms)\n\n  6 passing (1s)\n' "$title"
'''


def simulate(workflow_text, case_env, run_timeout=60):
    """Run the job's test, gate and summary scripts in a fresh tree. Returns
    (test exit code, gate exit code, {published relative paths}, tree)."""
    steps = job_steps(workflow_text)
    by_name = {s.get("name"): s for s in steps}
    test = by_name[TEST_STEP]
    gate = next(s for s in steps if s.get("id") == GATE_ID)
    summary = next((s for s in steps if "summarize_localnet_diagnostics.py" in s.get("run", "")), None)
    upload = next(s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@"))
    tmp = Path(tempfile.mkdtemp(prefix="gate-sim-"))
    shutil.copytree(ROOT / ".github/scripts", tmp / ".github/scripts",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (tmp / "arcium-psi").mkdir()
    (tmp / "runner").mkdir()
    (tmp / "home/.config/solana").mkdir(parents=True)
    (tmp / "home/.config/solana/id.json").write_text(str(list(os.urandom(64))).replace(" ", ""))
    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    (bin_dir / "arcium").write_text(FAKE_ARCIUM)
    (bin_dir / "docker").write_text("#!/usr/bin/env bash\nexec sleep 600\n")
    (bin_dir / "sudo").write_text("#!/usr/bin/env bash\nexit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    titles = tmp / "titles"
    titles.write_text("".join(f"{s} {t}\n" for s, t in re.findall(r"^run_scenario (\S+) '(.*)'$", test["run"], re.M)))

    def env_for(step):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "FAKE_", "LOCALNET_"))}
        env.update(PATH=f"{bin_dir}:{os.environ['PATH']}", HOME=str(tmp / "home"), RUNNER_TEMP=str(tmp / "runner"),
                   GITHUB_RUN_ID="777", GITHUB_RUN_ATTEMPT="1", FAKE_TITLES=str(titles),
                   FAKE_SCRIPTS=str(tmp / ".github/scripts"), PYTHONDONTWRITEBYTECODE="1")
        env.update(case_env)
        for k, v in step["env"].items():
            env[k] = v.replace("${{ runner.temp }}", str(tmp / "runner"))
        return env

    def run(step, timeout):
        shell = ["bash", "--noprofile", "--norc", "-eo", "pipefail"] if step.get("shell") == "bash" else ["bash", "-e"]
        cwd = tmp / step.get("working-directory", ".")
        script = tmp / "step.sh"
        script.write_text(step["run"])
        try:
            p = subprocess.run(shell + [str(script)], cwd=cwd, env=env_for(step), timeout=timeout,
                               capture_output=True, text=True, start_new_session=True)
            return p.returncode, p.stdout + p.stderr
        except subprocess.TimeoutExpired as e:
            subprocess.run(["pkill", "-KILL", "-f", str(tmp)], check=False)
            return "killed", (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")

    test_rc, test_out = run(test, run_timeout)
    gate_rc, gate_out = run(gate, 30)
    published = set()
    if gate_rc == 0:
        if summary is not None:
            sum_rc, sum_out = run(summary, 30)
            if sum_rc != 0:
                raise AssertionError(f"summary failed on a verified set:\n{sum_out}")
        root = Path(upload["with"]["path"].replace("${{ runner.temp }}", str(tmp / "runner")))
        published = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}
    return test_rc, gate_rc, published, tmp, test_out + gate_out


def self_test():
    failed = []

    def expect(cond, what):
        if not cond:
            failed.append(what)

    text = WORKFLOW.read_text()
    expect(check_workflow(text) == [], f"workflow check: {check_workflow(text)}")

    # Negative controls: each mutation must be rejected.
    mutations = {
        "unconditional upload": (f"if: {GATED}\n        uses: actions/upload-artifact",
                                 "if: always()\n        uses: actions/upload-artifact"),
        "raw directory uploaded": ("path: ${{ runner.temp }}/localnet-publish", "path: ${{ runner.temp }}/localnet-raw"),
        "step between gate and upload": ("      - name: Upload localnet diagnostics",
                                         "      - name: late copy\n        if: always()\n        run: echo hi\n"
                                         "      - name: Upload localnet diagnostics"),
        "copy into the publication directory": ("            rm -rf artifacts .anchor/test-ledger",
                                                '            cp -r "$raw" "$LOCALNET_PUBLISH_DIR/"\n'
                                                "            rm -rf artifacts .anchor/test-ledger"),
        "ungated summary": (f"if: {GATED}\n        env:\n          LOCALNET_PUBLISH_DIR",
                            "if: always()\n        env:\n          LOCALNET_PUBLISH_DIR"),
    }
    for what, (old, new) in mutations.items():
        if old not in text:
            failed.append(f"negative control {what}: pattern not found")
            continue
        expect(check_workflow(text.replace(old, new, 1)) != [], f"negative control not caught: {what}")

    scenarios = ["matches", "zero-hash", "invalid-count"]
    per_set = {"arcium-test.log", "validator.log", "artifacts-files.txt", "docker-events.jsonl", "MANIFEST.json"}

    def files_of(published, scenario):
        return {p.split("/", 1)[1] for p in published if p.startswith(scenario + "/")}

    cases = []
    # T1: all scenarios pass; every set is checked and published.
    rc, gate, pub, tmp, out = simulate(text, {})
    cases.append(tmp)
    expect(rc == 0 and gate == 0, f"T1 exit codes {rc} {gate}\n{out}")
    for s in scenarios:
        f = files_of(pub, s)
        expect(per_set <= f and f"computation-{s}.json" in f
               and f"artifacts/arx_node_logs/arx_log_05_10_2026_10-00-00_{s}.log" in f, f"T1 {s}: {f}")

    # T2: a scenario fails; its checked diagnostics are published, the step fails.
    rc, gate, pub, tmp, out = simulate(text, {"FAKE_FAIL": "zero-hash"})
    cases.append(tmp)
    expect(rc not in (0, "killed") and gate == 0, f"T2 exit codes {rc} {gate}")
    expect({p.split('/')[0] for p in pub} == {"matches", "zero-hash"}, f"T2 published {sorted(pub)}")
    log = tmp / "runner/localnet-publish/zero-hash/arcium-test.log"
    expect(log.exists() and "1 failing" in log.read_text(), "T2 failure log not published")

    # T3: the run's keys are missing or unreadable; that run is not published.
    rc, gate, pub, tmp, out = simulate(text, {"FAKE_NO_KEYS": "matches"})
    cases.append(tmp)
    expect(rc != 0 and gate != 0 and pub == set(), f"T3 no keys: {rc} {gate} {sorted(pub)}")
    rc, gate, pub, tmp, out = simulate(text, {"FAKE_BROKEN_KEY": "zero-hash"})
    cases.append(tmp)
    expect(rc != 0 and gate == 0 and {p.split('/')[0] for p in pub} == {"matches"},
           f"T3/T6 unreadable key: {rc} {gate} {sorted(pub)}")
    expect((tmp / "runner/localnet-raw/zero-hash/arcium-test.log").exists(), "T3/T6 raw set should exist unpublished")

    # T5: the step is killed before sanitising; nothing is published.
    rc, gate, pub, tmp, out = simulate(text, {"FAKE_HANG": "matches"}, run_timeout=5)
    cases.append(tmp)
    expect(rc == "killed" and gate != 0 and pub == set(), f"T5 interrupted: {rc} {gate} {sorted(pub)}")

    # T7: a synthetic leaked key is dropped, benign files survive.
    rc, gate, pub, tmp, out = simulate(text, {"FAKE_LEAK": "invalid-count"})
    cases.append(tmp)
    f = files_of(pub, "invalid-count")
    expect(rc == 0 and gate == 0 and "artifacts/arx_node_logs/leak.log" not in f and "arcium-test.log" in f,
           f"T7 leak: {rc} {gate} {sorted(f)}")

    # T6: after a successful check, an unchecked or changed set blocks the upload.
    rc, gate, pub, tmp, out = simulate(text, {})
    cases.append(tmp)
    pubdir = tmp / "runner/localnet-publish"
    shutil.copytree(tmp / "runner/localnet-raw/matches", pubdir / "unchecked")
    env = dict(os.environ, GITHUB_RUN_ID="777", GITHUB_RUN_ATTEMPT="1")
    verify = [sys.executable, str(ROOT / ".github/scripts/scrub_localnet_diagnostics.py"), "verify", str(pubdir)]
    expect(subprocess.run(verify, env=env, capture_output=True).returncode != 0, "T6 unchecked set accepted")
    shutil.rmtree(pubdir / "unchecked")
    expect(subprocess.run(verify, env=env, capture_output=True).returncode == 0, "T6 restored set rejected")
    (pubdir / "matches/arcium-test.log").write_text("changed after the check\n")
    expect(subprocess.run(verify, env=env, capture_output=True).returncode != 0, "T6 changed set accepted")

    for tmp in cases:
        shutil.rmtree(tmp, ignore_errors=True)
    for f in failed:
        print(f"SELF-TEST FAIL: {f}")
    print(f"self-test: workflow check, {len(mutations)} negative controls, simulated T1-T3, T5-T7; {len(failed)} failed")
    return 1 if failed else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:]:
        print(__doc__)
        return 2
    errors = check_workflow(WORKFLOW.read_text())
    for e in errors:
        print(f"::error::{e}")
    print(f"diagnostics publication gate: {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
