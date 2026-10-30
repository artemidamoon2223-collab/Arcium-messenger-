#!/usr/bin/env python3
"""Arcium QC engine: acceptance criteria, evidence and terminal states.

Deterministic, stdlib only. The terminal state of a task is computed here from
evidence this script produced itself, never from what an agent wrote:

  VERIFIED          every criterion passed on the current tree, the required
                    reviews are recorded for that tree, nothing is owner-gated
  FAILED            a criterion or a review failed; repair rounds remain
  NOT_VERIFIED      no evidence, stale evidence, a missing tool, a network
                    error, a manual criterion, or a review not yet recorded
  BLOCKED           the spec is missing, invalid, unlocked or changed after
                    lock; the evidence or the QC tool itself fails integrity
  ESCALATE_TO_OWNER repair rounds exhausted, or the diff touches an
                    owner-gated area the spec does not cite authority for

State lives in <git-dir>/arcium-qc/, outside the working tree: it is never
part of a diff and never committed. Records are HMAC-signed with a per-clone
key so that a hand-written or edited record is rejected. The key is readable
by anything with shell access: the signature stops fabricated or stale
records, not a deliberate forger with this clone's key.

This script grants nothing. It never commits, pushes, merges or dispatches
itself. `spec-check` refuses criteria whose program is a shell, `git` (other
than read-only subcommands), `gh`, `curl`, `wget`, `anchor`, `solana` or
`arcium`; that checks the program name only. A criterion is code run on this
machine (`python3 -c ...`, a script, a build) and can do anything its program
can: the criteria are reviewed, not sandboxed.
"""

import codecs
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

EXIT = {"VERIFIED": 0, "FAILED": 10, "NOT_VERIFIED": 11, "BLOCKED": 12, "ESCALATE_TO_OWNER": 13}
MAX_REPAIR_ROUNDS = 3
MAX_RUNS = 8  # hard cap on runs per spec, NOT_VERIFIED runs included
ACTIVE_TTL = 8 * 3600
TAIL_LINES = 40
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# ── Risk classification ──────────────────────────────────────────────────────
# (path prefix or exact path, classes). Every matching rule applies.
# `self-test` checks every prefix still exists, so a moved directory is
# reported instead of silently unclassified.
RULES = [
    ("crates/core-crypto/", {"CRYPTO"}),
    ("crates/core-storage/", {"DURABLE_STATE", "CRYPTO"}),
    ("crates/core-protocol/", {"DURABLE_STATE", "PROTOCOL"}),
    ("crates/mobile-ffi/src/contacts.rs", {"IDENTITY"}),
    ("crates/mobile-ffi/src/network", {"NETWORK", "PROTOCOL"}),
    ("crates/mobile-ffi/", {"FFI"}),
    ("crates/relay/", {"NETWORK", "PROTOCOL"}),
    ("crates/core-transport/", {"NETWORK"}),
    ("android/app/src/main/kotlin/com/arcium/messenger/security/", {"IDENTITY", "CRYPTO"}),
    ("android/app/src/main/kotlin/com/arcium/messenger/ffi/", {"FFI"}),
    ("android/", {"ANDROID_LIFECYCLE"}),
    ("arcium-psi/", {"PSI"}),
    (".github/", {"CI_INTEGRITY"}),
    (".cargo/", {"SUPPLY_CHAIN"}),
    (".devcontainer/", {"SUPPLY_CHAIN"}),
    ("CLAUDE.md", {"AGENT_CONTROL"}),
    (".claude/", {"AGENT_CONTROL"}),
]
SUPPLY_RE = re.compile(r"(^|/)(Cargo\.toml|Cargo\.lock|package\.json|package-lock\.json|"
                       r"[^/]*\.gradle\.kts|gradle-wrapper\.properties|rust-toolchain(\.toml)?)$|"
                       r"^\.git(ignore|attributes|modules)$")
# Agent and tooling control files that may not exist yet (so not in RULES).
CONTROL_RE = re.compile(r"^(\.mcp\.json|\.githooks/)")
# Changing these needs a separate, explicit Owner instruction (CLAUDE.md).
OWNER_GATED = {"CRYPTO", "PROTOCOL", "PSI", "CI_INTEGRITY", "SUPPLY_CHAIN", "AGENT_CONTROL"}
SECURITY_CLASSES = OWNER_GATED | {"DURABLE_STATE", "IDENTITY", "NETWORK", "FFI", "ANDROID_LIFECYCLE"}

# Owner-only operations: a criterion may never run them.
OWNER_ONLY_ARGV = [
    re.compile(r"^git$"), re.compile(r"^gh$"), re.compile(r"^(anchor|solana|arcium)$"),
    re.compile(r"^(curl|wget)$"),
]
OWNER_ONLY_GIT_OK = {"diff", "status", "log", "show", "rev-parse", "ls-files", "grep", "merge-base"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "env", "xargs", "eval"}
# Test runners whose exit code alone does not show that any test ran.
TEST_RUNNER_RE = re.compile(r"(^|\s)(cargo (\S+ )*(test|nextest)|\S*gradlew? (\S+ )*\S*[tT]est\S*|\S*mocha|"
                            r"\S*pytest|\S*jest|\S*vitest|(npm|pnpm|yarn) (run )?test\S*|go test|make \S*test\S*|"
                            r"\S*python3? (\S+ )*-m (unittest|pytest))(\s|$)")

# A non-zero exit whose output matches this is an environment problem
# (network, proxy, missing SDK), reported NOT_VERIFIED rather than FAILED...
NETWORK_ERR_RE = re.compile(
    r"Could not resolve host|Temporary failure in name resolution|Network is unreachable|"
    r"Connection refused|Connection timed out|connection reset|failed to download|"
    r"spurious network error|CONNECT tunnel failed|ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ETIMEDOUT|"
    r"Could not GET|Could not HEAD|Unable to tunnel through proxy|SSL connect error|"
    r"failed to get .* as a dependency|error sending request|Could not connect to server|"
    r"Couldn't connect to server|Failed to connect to|could not resolve plugin artifact|"
    r"Could not resolve all (files|dependencies|artifacts)|Could not download|SDK location not found", re.I)
# ...unless it also shows that tests ran and failed: then it is a real failure.
TEST_FAILED_RE = re.compile(
    r"^test result: FAILED|^---- \S+ stdout ----$|There were failing tests|tests completed, \d+ failed|"
    r"^FAILED \(|^AssertionError", re.M)


class QcError(Exception):
    def __init__(self, state, reason):
        super().__init__(reason)
        self.state, self.reason = state, reason


# ── Git and state helpers ────────────────────────────────────────────────────

def git(root, *args, binary=False):
    p = subprocess.run(["git", "-C", root, *args], capture_output=True)
    if p.returncode != 0:
        raise QcError("BLOCKED", "git %s failed: %s" % (" ".join(args), p.stderr.decode(errors="replace").strip()))
    return p.stdout if binary else p.stdout.decode(errors="replace")


def repo_root(start=None):
    start = start or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    p = subprocess.run(["git", "-C", start, "rev-parse", "--show-toplevel"], capture_output=True)
    if p.returncode != 0:
        raise QcError("BLOCKED", "not inside a git repository: %s" % start)
    return p.stdout.decode().strip()


def qc_dir(root):
    return os.path.join(git(root, "rev-parse", "--absolute-git-dir").strip(), "arcium-qc")


def state_dir(root):
    d = qc_dir(root)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def key(root):
    path = os.path.join(state_dir(root), "key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    except FileExistsError:
        pass
    with open(path, "rb") as f:
        return f.read()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sign(root, obj):
    body = dict(obj)
    body.pop("hmac", None)
    body["hmac"] = hmac.new(key(root), canon(body), hashlib.sha256).hexdigest()
    return body


def verify_sig(root, obj):
    if not isinstance(obj, dict) or "hmac" not in obj:
        return False
    body = dict(obj)
    mac = body.pop("hmac")
    good = hmac.new(key(root), canon(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(mac), good)


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def read_json(path):
    with open(path) as f:
        return json.load(f)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_hash():
    here = os.path.dirname(os.path.abspath(__file__))
    h = hashlib.sha256()
    for name in ("qc.py", "hooks.py"):
        p = os.path.join(here, name)
        h.update(name.encode() + b"\0" + (sha256_file(p).encode() if os.path.exists(p) else b"-"))
    return h.hexdigest()


def fingerprint(root):
    """HEAD, the tracked diff against it and every untracked, non-ignored file."""
    h = hashlib.sha256()
    h.update(git(root, "rev-parse", "HEAD").strip().encode())
    h.update(hashlib.sha256(git(root, "diff", "HEAD", "--binary", binary=True)).digest())
    for rel in sorted(x for x in git(root, "ls-files", "--others", "--exclude-standard", "-z").split("\0") if x):
        p = os.path.join(root, rel)
        h.update(rel.encode() + b"\0")
        h.update(sha256_file(p).encode() if os.path.isfile(p) else b"-")
    return h.hexdigest()


def changed_paths(root, base):
    # --no-renames: a moved file counts at its old path too.
    tracked = [x for x in git(root, "diff", "--name-only", "--no-renames", "-z", base).split("\0") if x]
    untracked = [x for x in git(root, "ls-files", "--others", "--exclude-standard", "-z").split("\0") if x]
    return sorted(set(tracked) | set(untracked))


def classify_paths(paths):
    out = {}
    for p in paths:
        cls = set()
        for prefix, c in RULES:
            if p == prefix or p.startswith(prefix):
                cls |= c
        if SUPPLY_RE.search(p):
            cls.add("SUPPLY_CHAIN")
        if CONTROL_RE.search(p):
            cls.add("AGENT_CONTROL")
        if not cls:
            cls.add("DOCS" if p.startswith("docs/") or p.endswith(".md") else "UNCLASSIFIED")
        out[p] = sorted(cls)
    return out


def added_lines(root, base):
    """(path, line) for every line the tree adds over `base`, new files included."""
    cur = None
    # quotePath off keeps non-ASCII names literal; names with control
    # characters, quotes or backslashes still arrive C-quoted ("b/...").
    for line in git(root, "-c", "core.quotePath=false", "diff", "-U0", "--no-renames", base).splitlines():
        if line.startswith("+++ "):
            name = line[4:]
            if name.startswith('"') and name.endswith('"'):
                name = codecs.escape_decode(name[1:-1].encode())[0].decode("utf-8", "replace")
            cur = name[2:] if name.startswith("b/") else None
        elif cur and line.startswith("+"):
            yield cur, line[1:]
    for rel in (x for x in git(root, "ls-files", "--others", "--exclude-standard", "-z").split("\0") if x):
        try:
            with open(os.path.join(root, rel), errors="replace") as f:
                for line in f:
                    yield rel, line.rstrip("\n")
        except (OSError, IsADirectoryError):
            continue


def content_flags(root, base):
    """Added lines that CLAUDE.md forbids outright."""
    flags = []
    for cur, add in added_lines(root, base):
        if cur.startswith(".github/") and re.search(r"continue-on-error:\s*true|\|\|\s*true\b", add):
            flags.append("CI_MASKED_GATE_CANDIDATE %s: %s" % (cur, add.strip()[:120]))
        if cur.startswith("arcium-psi/") and re.search(r"XChaCha|chacha20|Aes(Gcm|256)|aes-gcm", add, re.I):
            flags.append("CRYPTO_LAYERING message AEAD in PSI code %s" % cur)
        if (cur.startswith("crates/core-crypto/src/ratchet") or cur.startswith("crates/core-protocol/")) \
                and re.search(r"RescueCipher|rescue::", add):
            flags.append("CRYPTO_LAYERING RescueCipher on the message path %s" % cur)
        if re.search(r"#\[ignore\b|@Ignore\b|@Disabled\b|\b(it|describe|test)\.skip\(|\bx(it|describe)\(", add):
            flags.append("TEST_MASKING_CANDIDATE %s: %s" % (cur, add.strip()[:120]))
    return flags


def classify(root, base):
    paths = changed_paths(root, base)
    per = classify_paths(paths)
    classes = sorted({c for v in per.values() for c in v})
    reviews = []
    if paths:
        reviews.append("engineering-code-review")
    if set(classes) & (SECURITY_CLASSES | {"UNCLASSIFIED"}):
        reviews.append("arcium-security-review")
    return {
        "base": base,
        "paths": per,
        "classes": classes,
        "owner_gated": sorted(set(classes) & OWNER_GATED),
        "required_reviews": reviews,
        "load_with_security_review": sorted(
            (["mbr-integration"] if "DURABLE_STATE" in classes else [])
            + (["android-uniffi-bridge"] if "FFI" in classes else [])),
        "flags": content_flags(root, base),
    }


# ── Spec ─────────────────────────────────────────────────────────────────────

def spec_path(root, sid):
    return os.path.join(state_dir(root), "specs", sid + ".json")


def owner_only(argv):
    exe = os.path.basename(argv[0])
    if exe in SHELLS:
        return "shell wrappers are not allowed (%s): give the argv directly" % exe
    for rx in OWNER_ONLY_ARGV:
        if rx.match(exe):
            if exe == "git" and len(argv) > 1 and argv[1] in OWNER_ONLY_GIT_OK and \
                    not any(a.startswith(("-O", "--open-files-in-pager", "--output", "--ext-diff")) for a in argv):
                return None
            return "owner-only or network-writing tool %r is not allowed in a criterion" % exe
    joined = " ".join(argv)
    if re.search(r"\b(workflow_dispatch|merge_pull_request|actions_run_trigger)\b", joined):
        return "owner-only operation named in a criterion"
    return None


def load_spec(root, sid):
    if not ID_RE.match(sid or ""):
        raise QcError("BLOCKED", "invalid spec id %r" % sid)
    path = spec_path(root, sid)
    if not os.path.exists(path):
        raise QcError("BLOCKED", "no spec %s: write acceptance criteria first (qc.py spec-init)" % sid)
    try:
        spec = read_json(path)
    except (OSError, ValueError) as e:
        raise QcError("BLOCKED", "spec %s is not valid JSON: %s" % (sid, e))
    errs = []
    if spec.get("id") != sid:
        errs.append("id must equal the file name")
    if not SHA_RE.match(str(spec.get("base", ""))):
        errs.append("base must be a 40-hex commit SHA")
    if not str(spec.get("owner_instruction", "")).strip():
        errs.append("owner_instruction must quote the Owner's instruction for this task")
    auth = spec.get("owner_authorizes", [])
    if not isinstance(auth, list) or any(a not in OWNER_GATED for a in auth):
        errs.append("owner_authorizes must list only %s" % sorted(OWNER_GATED))
    rounds = spec.get("max_repair_rounds", MAX_REPAIR_ROUNDS)
    if not isinstance(rounds, int) or not 0 <= rounds <= MAX_REPAIR_ROUNDS:
        errs.append("max_repair_rounds must be 0..%d" % MAX_REPAIR_ROUNDS)
    crit = spec.get("criteria")
    if not isinstance(crit, list) or not crit:
        errs.append("criteria must be a non-empty list")
        crit = []
    seen = set()
    automatic = 0
    for i, c in enumerate(crit):
        where = "criteria[%d]" % i
        if not isinstance(c, dict) or not ID_RE.match(str(c.get("id", "")).lower()) or c.get("id") in seen:
            errs.append("%s: needs a unique id" % where)
            continue
        seen.add(c["id"])
        if not str(c.get("description", "")).strip():
            errs.append("%s: needs a description" % where)
        if c.get("manual"):
            continue
        argv = c.get("command")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
            errs.append("%s: command must be a non-empty argv list of strings" % where)
            continue
        bad = owner_only(argv)
        if bad:
            errs.append("%s: %s" % (where, bad))
        if TEST_RUNNER_RE.search(" ".join(argv)) and not c.get("must_match"):
            errs.append("%s: a test run needs must_match proving tests ran (a filter matching nothing exits 0)"
                        % where)
        cwd = c.get("cwd", ".")
        if os.path.isabs(cwd) or ".." in cwd.split("/"):
            errs.append("%s: cwd must be relative to the repository root" % where)
        for rx in c.get("must_match", []) + c.get("must_not_match", []):
            try:
                re.compile(rx)
            except re.error as e:
                errs.append("%s: bad regex %r: %s" % (where, rx, e))
        automatic += 1
    if automatic == 0:
        errs.append("at least one criterion must be executable")
    if errs:
        raise QcError("BLOCKED", "spec %s invalid: %s" % (sid, "; ".join(errs)))
    return spec, sha256_file(path)


SPEC_TEMPLATE = {
    "id": None,
    "title": "<one line>",
    "base": None,
    "owner_instruction": "<verbatim quote of the Owner instruction that authorizes this task>",
    "owner_authorizes": [],
    "max_repair_rounds": MAX_REPAIR_ROUNDS,
    "criteria": [
        {"id": "ac-rust-tests", "description": "workspace tests pass (CLAUDE.md, Команды проверки)",
         "command": ["cargo", "test", "--workspace", "--locked"], "requires": ["cargo"], "timeout": 3600,
         "must_match": ["test result: ok\\. [1-9][0-9]* passed; 0 failed"],
         "must_not_match": ["test result: FAILED"]},
        {"id": "ac-clippy", "description": "clippy clean",
         "command": ["cargo", "clippy", "--workspace", "--locked", "--", "-D", "warnings"],
         "requires": ["cargo"], "timeout": 3600},
    ],
}


# ── State ────────────────────────────────────────────────────────────────────

def state_path(root, sid):
    return os.path.join(state_dir(root), "runs", sid, "state.json")


def load_state(root, sid):
    p = state_path(root, sid)
    if not os.path.exists(p):
        return None
    st = read_json(p)
    if not verify_sig(root, st):
        raise QcError("BLOCKED", "state of %s fails its integrity check (edited or forged)" % sid)
    return st


def save_state(root, sid, st):
    os.makedirs(os.path.dirname(state_path(root, sid)), mode=0o700, exist_ok=True)
    write_json(state_path(root, sid), sign(root, st))


def preconditions(root, sid):
    """Spec, lock, tool integrity, owner gates, budget. Raises QcError."""
    spec, spec_sha = load_spec(root, sid)
    st = load_state(root, sid)
    if st is None:
        raise QcError("BLOCKED", "spec %s is not locked: lock it before implementing (qc.py lock)" % sid)
    if st["spec_sha256"] != spec_sha:
        raise QcError("BLOCKED", "spec %s changed after it was locked: criteria cannot move mid-task" % sid)
    if st["tool_sha256"] != tool_hash():
        raise QcError("BLOCKED", "the QC tool (qc.py/hooks.py) changed after the spec was locked")
    if subprocess.run(["git", "-C", root, "merge-base", "--is-ancestor", spec["base"], "HEAD"],
                      capture_output=True).returncode != 0:
        raise QcError("BLOCKED", "base %s is not an ancestor of HEAD" % spec["base"][:12])
    cls = classify(root, spec["base"])
    missing = sorted(set(cls["owner_gated"]) - set(spec.get("owner_authorizes", [])))
    if missing:
        raise QcError("ESCALATE_TO_OWNER", "the diff touches owner-gated areas %s that the spec's owner_instruction "
                      "does not authorize; ask the Owner" % missing)
    if cls["flags"]:
        raise QcError("ESCALATE_TO_OWNER", "forbidden pattern(s): %s" % "; ".join(cls["flags"]))
    limit = 1 + spec.get("max_repair_rounds", MAX_REPAIR_ROUNDS)
    if st["failed_runs"] >= limit:
        raise QcError("ESCALATE_TO_OWNER", "%d failed attempts: the repair budget (%d rounds) is exhausted"
                      % (st["failed_runs"], limit - 1))
    return spec, spec_sha, st, cls


# ── Running criteria ─────────────────────────────────────────────────────────

def network_ok(url, timeout=8):
    try:
        urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=timeout)
        return True, ""
    except urllib.error.HTTPError as e:
        return (e.code < 500 and e.code not in (403, 407)), "HTTP %d" % e.code
    except Exception as e:  # noqa: BLE001 - any failure means "not reachable"
        return False, "%s" % e


def run_criterion(root, c):
    res = {"id": c["id"], "description": c["description"]}
    if c.get("manual"):
        res.update(status="NOT_VERIFIED", reason="manual criterion: needs a person or a device")
        return res
    for tool in c.get("requires", []):
        if shutil.which(tool) is None:
            res.update(status="NOT_VERIFIED", reason="required tool %r is not installed" % tool)
            return res
    any_env = c.get("requires_env_any", [])
    if any_env and not any(os.environ.get(e) for e in any_env):
        res.update(status="NOT_VERIFIED", reason="none of %s is set" % any_env)
        return res
    for rel in c.get("requires_path", []):
        if not os.path.exists(os.path.join(root, rel)):
            res.update(status="NOT_VERIFIED", reason="required path %s is missing" % rel)
            return res
    if c.get("network"):
        ok, why = network_ok(c.get("network_probe", "https://index.crates.io/config.json"))
        if not ok:
            res.update(status="NOT_VERIFIED", reason="network preflight failed: %s" % why)
            return res
    argv = c["command"]
    cwd = os.path.join(root, c.get("cwd", "."))
    env = dict(os.environ)
    env.update({k: str(v) for k, v in c.get("env", {}).items()})
    t0 = time.time()
    try:
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=c.get("timeout", 1800))
        rc, out, err = p.returncode, p.stdout, p.stderr
        timed_out = False
    except FileNotFoundError:
        res.update(status="NOT_VERIFIED", reason="command not found: %s" % argv[0])
        return res
    except subprocess.TimeoutExpired as e:
        rc, out, err, timed_out = None, e.stdout or b"", e.stderr or b"", True
    text = (out + b"\n" + err).decode(errors="replace")
    res.update(argv=argv, cwd=c.get("cwd", "."), exit_code=rc, seconds=round(time.time() - t0, 2),
               stdout_sha256=hashlib.sha256(out).hexdigest(), stderr_sha256=hashlib.sha256(err).hexdigest(),
               tail="\n".join(text.splitlines()[-TAIL_LINES:]))
    if timed_out:
        net = c.get("network") or NETWORK_ERR_RE.search(text)
        res.update(status="NOT_VERIFIED" if net else "FAIL",
                   reason="timed out after %ss%s" % (c.get("timeout", 1800), " (network)" if net else ""))
        return res
    problems = []
    if rc != c.get("expect_exit", 0):
        problems.append("exit code %s, expected %s" % (rc, c.get("expect_exit", 0)))
    for rx in c.get("must_match", []):
        if not re.search(rx, text, re.M):
            problems.append("output lacks /%s/" % rx)
    for rx in c.get("must_not_match", []):
        if re.search(rx, text, re.M):
            problems.append("output contains /%s/" % rx)
    if not problems:
        res.update(status="PASS")
    elif rc not in (0, None) and NETWORK_ERR_RE.search(text) and not TEST_FAILED_RE.search(text):
        res.update(status="NOT_VERIFIED", reason="environment error in output (network, proxy or SDK): "
                   + NETWORK_ERR_RE.search(text).group(0))
    else:
        res.update(status="FAIL", reason="; ".join(problems))
    return res


def cmd_run(root, sid):
    spec, spec_sha, st, cls = preconditions(root, sid)
    if len(st["runs"]) >= MAX_RUNS:
        raise QcError("ESCALATE_TO_OWNER", "%d runs recorded: the run cap is reached" % len(st["runs"]))
    fp_before = fingerprint(root)
    results = [run_criterion(root, c) for c in spec["criteria"]]
    fp_after = fingerprint(root)
    statuses = {r["status"] for r in results}
    if fp_before != fp_after:
        outcome, why = "NOT_VERIFIED", "the tree changed while the criteria ran"
    elif "FAIL" in statuses:
        outcome, why = "FAILED", "failed: " + ", ".join(r["id"] for r in results if r["status"] == "FAIL")
    elif "NOT_VERIFIED" in statuses:
        outcome, why = "NOT_VERIFIED", "; ".join("%s: %s" % (r["id"], r["reason"])
                                                  for r in results if r["status"] == "NOT_VERIFIED")
    else:
        outcome, why = "PASS", "all criteria passed"
    n = len(st["runs"]) + 1
    ev = sign(root, {"kind": "run", "spec_id": sid, "spec_sha256": spec_sha, "n": n, "time": int(time.time()),
                     "fingerprint": fp_after, "fingerprint_before": fp_before, "head": git(root, "rev-parse", "HEAD").strip(),
                     "classification": cls, "results": results, "outcome": outcome, "why": why})
    ev_path = os.path.join(os.path.dirname(state_path(root, sid)), "run-%d.json" % n)
    write_json(ev_path, ev)
    st["runs"].append({"n": n, "outcome": outcome, "sha256": sha256_file(ev_path)})
    if outcome == "FAILED":
        st["failed_runs"] += 1
    save_state(root, sid, st)
    return verdict(root, sid)


# ── Reviews ──────────────────────────────────────────────────────────────────

REVIEW_BLOCKS = {
    "engineering-code-review": ("KARPATHY_REVIEW_RESULT", "KARPATHY_REVIEW_END"),
    "arcium-security-review": ("ARCIUM_SECURITY_REVIEW", "ARCIUM_SECURITY_REVIEW_END"),
}


def parse_review(skill, text):
    start, end = REVIEW_BLOCKS[skill]
    m = re.search(re.escape(start) + r"\n(.*?)\n" + re.escape(end), text, re.S)
    if not m:
        raise QcError("NOT_VERIFIED", "no %s ... %s block in the review" % (start, end))
    block = m.group(1)
    complete = re.search(r"^complete:\s*(yes|no)\s*$", block, re.M)
    blocking = []
    if skill == "engineering-code-review":
        for p in ("think_before_coding", "simplicity_first", "surgical_changes", "goal_driven"):
            v = re.search(r"^%s:\s*(pass|warning|fail)\b" % p, block, re.M)
            if not v:
                raise QcError("NOT_VERIFIED", "review lacks a verdict for %s" % p)
            if v.group(1) == "fail":
                blocking.append(p)
    else:
        # Any CRITICAL or HIGH in the findings section blocks, whatever its layout.
        section = re.search(r"^findings:(.*?)^known_findings:", block, re.M | re.S)
        if not section:
            raise QcError("NOT_VERIFIED", "security review lacks its findings section")
        blocking = re.findall(r"\b(CRITICAL|HIGH)\b", section.group(1))
    return {"complete": bool(complete and complete.group(1) == "yes"), "blocking": blocking,
            "block_sha256": hashlib.sha256(block.encode()).hexdigest()}


def cmd_review_record(root, sid, skill, text):
    if skill not in REVIEW_BLOCKS:
        raise QcError("BLOCKED", "unknown review skill %s" % skill)
    spec, spec_sha, st, cls = preconditions(root, sid)
    parsed = parse_review(skill, text)
    block = text[text.index(REVIEW_BLOCKS[skill][0]):]
    target = re.search(r"^target:\s*(\S+)", block, re.M)
    if not target or not target.group(1).startswith(spec["base"]):
        raise QcError("NOT_VERIFIED", "review target must start with the spec base %s" % spec["base"])
    missing = [p for p in cls["paths"] if p not in block]
    if missing:
        raise QcError("NOT_VERIFIED", "review does not name every changed path; missing %s" % missing[:10])
    n = len(st.get("reviews", [])) + 1
    rec = sign(root, {"kind": "review", "spec_id": sid, "spec_sha256": spec_sha, "skill": skill, "n": n,
                      "time": int(time.time()), "fingerprint": fingerprint(root), "text": text, **parsed})
    path = os.path.join(os.path.dirname(state_path(root, sid)), "review-%d.json" % n)
    write_json(path, rec)
    st.setdefault("reviews", []).append({"n": n, "skill": skill, "sha256": sha256_file(path)})
    if parsed["blocking"]:
        st["failed_runs"] += 1
    save_state(root, sid, st)
    return verdict(root, sid)


# ── Verdict ──────────────────────────────────────────────────────────────────

def load_record(root, sid, name, expect_sha):
    path = os.path.join(os.path.dirname(state_path(root, sid)), name)
    if not os.path.exists(path) or sha256_file(path) != expect_sha:
        raise QcError("BLOCKED", "%s is missing or differs from the state ledger" % name)
    rec = read_json(path)
    if not verify_sig(root, rec):
        raise QcError("BLOCKED", "%s fails its integrity check (edited or fabricated)" % name)
    return rec


def verdict(root, sid):
    try:
        return _verdict(root, sid)
    except QcError as e:
        return e.state, e.reason


def _verdict(root, sid):
    spec, spec_sha, st, cls = preconditions(root, sid)
    if not st["runs"]:
        return "NOT_VERIFIED", "no evidence: run the criteria (qc.py run %s)" % sid
    last = st["runs"][-1]
    ev = load_record(root, sid, "run-%d.json" % last["n"], last["sha256"])
    if ev["spec_sha256"] != spec_sha:
        return "BLOCKED", "the evidence is for another version of the spec"
    fp = fingerprint(root)
    if ev["fingerprint"] != fp:
        return "NOT_VERIFIED", "stale evidence: the tree changed after run %d; run again" % ev["n"]
    if ev["outcome"] == "FAILED":
        left = 1 + spec.get("max_repair_rounds", MAX_REPAIR_ROUNDS) - st["failed_runs"]
        return "FAILED", "%s; %d repair round(s) left" % (ev["why"], left)
    if ev["outcome"] != "PASS":
        return "NOT_VERIFIED", ev["why"]
    pending, incomplete = [], []
    for skill in cls["required_reviews"]:
        recs = [load_record(root, sid, "review-%d.json" % r["n"], r["sha256"])
                for r in st.get("reviews", []) if r["skill"] == skill]
        current = [r for r in recs if r["fingerprint"] == fp]
        if not current:
            pending.append(skill + (" (stale)" if recs else ""))
            continue
        # A later record never erases a blocking one for the same tree.
        blocking = [b for r in current for b in r["blocking"]]
        if blocking:
            left = 1 + spec.get("max_repair_rounds", MAX_REPAIR_ROUNDS) - st["failed_runs"]
            return "FAILED", "%s found %s; %d repair round(s) left" % (skill, blocking, left)
        if not current[-1]["complete"]:
            incomplete.append(skill)
    if pending or incomplete:
        return "NOT_VERIFIED", "criteria passed; review %s%s" % (
            ("pending: %s" % pending) if pending else "", (" incomplete: %s" % incomplete) if incomplete else "")
    granted = sorted(set(cls["owner_gated"]) & set(spec.get("owner_authorizes", [])))
    return "VERIFIED", "run %d passed every criterion on this tree; reviews recorded: %s%s" % (
        ev["n"], cls["required_reviews"] or "none required",
        ("; owner authority self-declared in the spec for %s: confirm it against the Owner's instruction"
         % granted) if granted else "")


# ── Activation (for the optional hooks) ─────────────────────────────────────

def active_path(root):
    return os.path.join(state_dir(root), "active.json")


def active_loop(root):
    """The active spec id, or None. Creates nothing."""
    p = os.path.join(qc_dir(root), "active.json")
    if not os.path.exists(p):
        return None
    try:
        a = read_json(p)
    except (OSError, ValueError):
        return None
    if not verify_sig(root, a) or time.time() > a.get("expires", 0):
        return None
    return a.get("spec_id")


# ── CLI ──────────────────────────────────────────────────────────────────────

def cmd_lock(root, sid):
    spec, spec_sha = load_spec(root, sid)
    if load_state(root, sid) is not None:
        raise QcError("BLOCKED", "spec %s is already locked; a new task needs a new id" % sid)
    head = git(root, "rev-parse", "HEAD").strip()
    if head != spec["base"]:
        raise QcError("BLOCKED", "lock requires HEAD == base (%s); HEAD is %s" % (spec["base"][:12], head[:12]))
    if git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise QcError("BLOCKED", "lock requires a clean tree: criteria are fixed before implementation")
    save_state(root, sid, {"spec_id": sid, "spec_sha256": spec_sha, "tool_sha256": tool_hash(),
                           "locked_at": int(time.time()), "lock_fingerprint": fingerprint(root),
                           "runs": [], "reviews": [], "failed_runs": 0})
    return "NOT_VERIFIED", "spec %s locked at %s; implement, then run the criteria" % (sid, head[:12])


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, args = argv[1], argv[2:]
    try:
        root = repo_root()
        if cmd == "classify":
            # A spec id stands for its base; otherwise any commit-ish.
            if args and ID_RE.match(args[0]) and os.path.exists(spec_path(root, args[0])):
                base = load_spec(root, args[0])[0]["base"]
            else:
                base = args[0] if args else git(root, "rev-parse", "HEAD").strip()
            print(json.dumps(classify(root, base), indent=1))
            return 0
        if cmd == "spec-init":
            sid = args[0]
            if not ID_RE.match(sid):
                raise QcError("BLOCKED", "invalid id %r" % sid)
            p = spec_path(root, sid)
            if os.path.exists(p):
                raise QcError("BLOCKED", "%s exists" % p)
            os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
            t = dict(SPEC_TEMPLATE, id=sid, base=git(root, "rev-parse", "HEAD").strip())
            write_json(p, t)
            print(p)
            return 0
        if cmd == "spec-path":
            print(spec_path(root, args[0]))
            return 0
        if cmd == "spec-check":
            spec, sha = load_spec(root, args[0])
            print("spec %s valid, sha256 %s, %d criteria" % (args[0], sha, len(spec["criteria"])))
            return 0
        if cmd == "self-test":
            missing = [p for p, _ in RULES if not os.path.exists(os.path.join(root, p.rstrip("/")))]
            print(json.dumps({"stale_rules": missing}))
            return 1 if missing else 0
        if cmd == "activate":
            sid = args[0]
            load_spec(root, sid)
            write_json(active_path(root), sign(root, {"spec_id": sid, "expires": int(time.time()) + ACTIVE_TTL}))
            print("QC loop %s active for %dh (hooks, if enabled, now apply)" % (sid, ACTIVE_TTL // 3600))
            return 0
        if cmd == "deactivate":
            sid = active_loop(root)
            if sid is not None and verdict(root, sid)[0] == "FAILED":
                raise QcError("FAILED", "loop %s is mid-repair: it ends at a terminal report, or when its "
                              "activation expires" % sid)
            if os.path.exists(active_path(root)):
                os.remove(active_path(root))
            print("no QC loop active")
            return 0
        if cmd == "evidence":
            st = load_state(root, args[0])
            if not st or not st["runs"]:
                raise QcError("NOT_VERIFIED", "no evidence for %s" % args[0])
            last = st["runs"][-1]
            n = last["n"]
            rec = load_record(root, args[0], "run-%d.json" % n, last["sha256"])
            for r in rec["results"]:
                print("%-24s %-12s %s" % (r["id"], r["status"], r.get("reason", "")))
                if r["status"] == "FAIL":
                    print("\n".join("    | " + x for x in r.get("tail", "").splitlines()[-20:]))
            print("run %d: %s (%s)" % (n, rec["outcome"], rec["why"]))
            return 0
        if cmd == "lock":
            state, why = cmd_lock(root, args[0])
        elif cmd == "run":
            state, why = cmd_run(root, args[0])
        elif cmd == "verdict":
            state, why = verdict(root, args[0])
        elif cmd == "review-record":
            state, why = cmd_review_record(root, args[0], args[1], sys.stdin.read())
        else:
            print("unknown command %s" % cmd, file=sys.stderr)
            return 2
    except QcError as e:
        state, why = e.state, e.reason
    except IndexError:
        print("usage: qc.py <command> <spec-id> (see the module docstring)", file=sys.stderr)
        return 2
    print("QC_STATE: %s | %s" % (state, why))
    return EXIT[state]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
