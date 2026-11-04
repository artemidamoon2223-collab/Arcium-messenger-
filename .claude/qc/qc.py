#!/usr/bin/env python3
"""Arcium QC engine: acceptance criteria, evidence and terminal states.

Deterministic, stdlib only. The terminal state of a task is computed here from
the results of commands this script ran itself and from the recorded review
blocks, never from an agent's own report of the result. The criteria, the
spec's owner_authorizes and the review text are still written by agents:

  VERIFIED          every criterion passed on the current tree, the required
                    reviews are recorded for that tree, and every owner-gated
                    class the diff touches is listed in the spec's
                    owner_authorizes. That authority is self-declared by the
                    spec's author; the verdict names it for the Owner to check
  FAILED            a criterion or a review failed; repair rounds remain
  NOT_VERIFIED      no evidence, stale evidence, a missing tool, a network
                    error, a manual criterion, or a review not yet recorded
  BLOCKED           the spec is missing, invalid, unlocked or changed after
                    lock; the evidence or the QC tool itself fails integrity
  ESCALATE_TO_OWNER repair rounds exhausted, the run cap reached without a
                    result that a review alone could still complete, or the
                    diff touches an owner-gated area the spec does not cite
                    authority for

What changed is computed from the bytes on disk against the base commit's
tree, not from `git diff` or `git status`, and git runs without the user's
global configuration or GIT_* variables: diff and colour settings, external
diff drivers, attributes, replace refs, fsmonitor, assume-unchanged and
skip-worktree flags, .git/info/exclude and core.excludesFile hide nothing.
No ignore rule hides anything: every file on disk is part of the tree
except the root's .git and the exact build-output directories in
TRUSTED_BUILD_DIRS (target/, the Gradle and Anchor build directories,
node_modules/). A nested git repository anywhere, or a gitlink (submodule or
embedded repository) in the tree or the index, is BLOCKED: its contents
cannot be checked. A link to a file whose contents are not listed at a path
of their own (out of the clone, in .git or in a trusted build directory) is
fingerprinted with that file's contents; a link to such a directory is
BLOCKED.
An untracked .claude/settings.local.json (where the Owner enables the hooks)
is not part of the change, but it is hashed at lock: any change to it after
lock is ESCALATE_TO_OWNER.

A run that is still going, or was interrupted (killed, crashed), leaves
NOT_VERIFIED until a later run completes. An interrupted run counts as a
failed repair round and against the run cap, so killing a run never saves
budget; a run or review whose signed record was written before the crash
is kept with its outcome. One run, lock or review-record per spec at a
time: a second one is refused while the first holds the lock on the spec's
record directory. Unreadable state is BLOCKED, and so is any internal error:
nothing here turns a crash into VERIFIED. A review is recorded only for a
tree whose last run passed, and only if its block quotes that tree's
fingerprint (`qc.py status <id>` prints it). Each run records the tree
object of the tree it ran on, kept by refs/arcium-qc/<id>/run-<n> (for
`git diff <base> <tree>`), the program it ran and any Cargo configuration
outside the repository; a Cargo configuration in a directory above the
repository (not CARGO_HOME), or a CARGO_TARGET_*_RUNNER variable, makes a
cargo criterion NOT_VERIFIED. An active loop is deactivated, or replaced by
another activation, only once its verdict is VERIFIED; in every other state
(and while its activation record is unreadable) the Owner ends it by
deleting <git-dir>/arcium-qc/active.json, or it expires after 8 hours.
Besides the files on disk, the fingerprint covers the git state a criterion
could read: the index entries, the clone's own config and info/attributes.

State lives in <git-dir>/arcium-qc/, outside the working tree: it is never
part of a diff and never committed. Records are HMAC-signed with a per-clone
key so that a hand-written or edited record is rejected, and never
overwritten. A state file rolled back to an older signed copy, or deleted
and locked again, is BLOCKED while the later records remain; deleting the
whole directory (or the records too) cannot be detected locally. The key is
readable by anything with shell access: the signature stops fabricated or
stale records, not a deliberate forger with this clone's key.

This script grants nothing. It never commits, pushes, merges or dispatches
itself. `spec-check` refuses criteria whose program is a shell, `git` (other
than read-only subcommands), `gh`, `curl`, `wget`, `anchor`, `solana` or
`arcium`; that checks the program name only. A criterion is code run on this
machine (`python3 -c ...`, a script, a build) and can do anything its program
can: the criteria are reviewed, not sandboxed. What it runs with outside the
tree (the installed toolchain, ~/.cargo/config.toml, environment variables
such as RUSTC_WRAPPER) is recorded, not verified. A Claude Code permission
rule saved into an untracked .claude/settings.local.json during a loop
changes its hash and escalates, by design.
"""

import contextlib
import difflib
import fcntl
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
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
                       r"[^/]*\.gradle\.kts|gradle-wrapper\.properties|rust-toolchain(\.toml)?|"
                       r"\.git(ignore|attributes|modules)|\.cargo/config(\.toml)?)$")
# Agent and tooling control files that may not exist yet (so not in RULES).
CONTROL_RE = re.compile(r"^(\.mcp\.json|\.githooks/|\.pi/)|(^|/)(CLAUDE[^/]*\.md|AGENTS\.md)$")
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
TEST_RUNNER_RE = re.compile(r"(^|\s)(cargo (\S+ )*(test|t|nextest)|\S*gradlew? (\S+ )*\S*[tT]est\S*|\S*mocha|"
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
    r"^FAILED \(|^AssertionError|^\s*[1-9][0-9]* failing$", re.M)


def crash_point(name):
    """Tests only: QC_TEST_CRASH_AT=<name> kills this process here, as a power cut or a kill would.
    It can only stop qc.py itself, which anyone able to set the variable can already do."""
    if os.environ.get("QC_TEST_CRASH_AT") == name:
        os.kill(os.getpid(), 9)


class QcError(Exception):
    def __init__(self, state, reason):
        super().__init__(reason)
        self.state, self.reason = state, reason


# ── Git and state helpers ────────────────────────────────────────────────────
# Git is asked only for object and path lists, never for a diff or a status:
# what changed is computed here from the bytes on disk against the commit's
# tree. Diff options, external diff and textconv drivers, colour, path
# prefixes, replace refs, fsmonitor and the index's assume-unchanged and
# skip-worktree flags therefore change nothing. Git runs without the user's
# global and system configuration, without GIT_* variables and without
# hooks. No ignore rule hides a path: the files on disk are listed by walking
# the tree (TRUSTED_BUILD_DIRS aside), not by asking git which are ignored.

GIT_OPTS = ["--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-c", "core.quotePath=false", "-c", "core.excludesFile=" + os.devnull, "-c", "color.ui=never",
            "-c", "core.hooksPath=" + os.devnull]


def git_env(extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS="1",
               GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    env.update(extra or {})
    return env


def git(root, *args, binary=False, stdin=None, env=None):
    p = subprocess.run(["git", *GIT_OPTS, "-C", root, *args], capture_output=True, input=stdin,
                       env=git_env(env))
    if p.returncode != 0:
        raise QcError("BLOCKED", "git %s failed: %s" % (" ".join(args), p.stderr.decode(errors="replace").strip()))
    return p.stdout if binary else p.stdout.decode(errors="replace")


def repo_root(start=None):
    start = start or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    p = subprocess.run(["git", *GIT_OPTS, "-C", start, "rev-parse", "--show-toplevel"], capture_output=True,
                       env=git_env())
    if p.returncode != 0:
        raise QcError("BLOCKED", "not inside a git repository: %s" % start)
    return p.stdout.decode().strip()


def qc_dir(root):
    return os.path.join(git(root, "rev-parse", "--absolute-git-dir").strip(), "arcium-qc")


def state_dir(root):
    d = qc_dir(root)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def key(root):
    path = os.path.join(state_dir(root), "key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
            f.flush()
            os.fsync(f.fileno())
        fsync_dir(os.path.dirname(path))
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


def write_json(path, obj, exclusive=False):
    """Atomic and durable: the file and its directory entry reach the disk.
    `exclusive`: the file must not exist yet; an existing record is never replaced."""
    tmp = "%s.%d.tmp" % (path, os.getpid())
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    try:
        if exclusive:
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise QcError("BLOCKED", "%s already exists: records are never overwritten" % os.path.basename(path))
        else:
            os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    fsync_dir(os.path.dirname(path) or ".")


def read_json(path):
    with open(path) as f:
        return json.load(f)


def read_record(path, what):
    """A record written by this tool. Unreadable or cut short is BLOCKED, never a crash."""
    try:
        return read_json(path)
    except (OSError, ValueError) as e:
        raise QcError("BLOCKED", "%s is unreadable (corrupt or cut short): %s" % (what, e))


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


def object_format(root):
    return git(root, "rev-parse", "--show-object-format").strip() or "sha1"


def tree_entries(root, rev):
    """{path: (mode, oid)} for every entry of `rev`'s tree (gitlinks as mode 160000)."""
    out = {}
    for rec in git(root, "ls-tree", "-r", "-z", "--full-tree", rev).split("\0"):
        if rec:
            meta, path = rec.split("\t", 1)
            mode, _type, oid = meta.split()
            out[path] = (mode, oid)
    return out


# Untracked files that are a person's local configuration, never part of a
# change: Claude Code's per-user settings, where the Owner enables the
# candidate hooks. Only while untracked; a tracked one is an ordinary path.
LOCAL_ONLY = {".claude/settings.local.json"}

# The trusted build-output policy. These exact directories (from the root, real
# directories only, never a link) hold build output that the repository's own
# tracked .gitignore files exclude; their untracked contents are not part of the
# tree or its fingerprint. Nothing else is trusted: every other file on disk,
# ignored or not, is listed, fingerprinted and classified, and a file tracked
# inside one of these directories is still checked. `self-test` checks that each
# one is ignored by a tracked .gitignore and that its parent directory exists.
TRUSTED_BUILD_DIRS = (
    "target",
    "android/.gradle", "android/build", "android/app/build", "android/app/.cxx",
    "android/app/.externalNativeBuild",
    "arcium-psi/target", "arcium-psi/programs/arcium-psi/target", "arcium-psi/encrypted-ixs/target",
    "arcium-psi/.anchor", "arcium-psi/build", "arcium-psi/encrypted-ixs/build", "arcium-psi/artifacts",
    "arcium-psi/test-ledger", "arcium-psi/tests/node_modules", "arcium-psi/tests/dist",
)
# Above this many files outside the trusted directories, listing is refused rather than slow.
MAX_LISTED = 100000


def split0(text):
    return [x for x in text.split("\0") if x]


def in_trusted_dir(rel):
    return any(rel == d or rel.startswith(d + "/") for d in TRUSTED_BUILD_DIRS)


def _walk_error(e):
    raise QcError("BLOCKED", "cannot read %s (%s): its contents cannot be checked" % (e.filename, e.strerror))


def disk_paths(root):
    """Every file, link and special file on disk, except the root's own .git and the trusted build
    directories. A .git anywhere else is a nested repository, whose contents cannot be checked: BLOCKED.
    Links are listed as themselves (never followed here); an unreadable directory is BLOCKED."""
    out = set()
    for d, dirs, files in os.walk(root, onerror=_walk_error):
        rel_d = os.path.relpath(d, root)
        rel_d = "" if rel_d == "." else rel_d + "/"
        if not rel_d:
            dirs[:] = [x for x in dirs if x != ".git"]
            files = [x for x in files if x != ".git"]
        elif ".git" in dirs or ".git" in files:
            raise QcError("BLOCKED", "nested git repository %s: its contents cannot be checked; move it out "
                          "of the clone" % rel_d)
        keep = []
        for x in dirs:
            if os.path.islink(os.path.join(d, x)):
                out.add(rel_d + x)
            elif (rel_d + x) not in TRUSTED_BUILD_DIRS:
                keep.append(x)
        dirs[:] = keep
        out.update(rel_d + f for f in files)
        if len(out) > MAX_LISTED:
            raise QcError("BLOCKED", "more than %d files outside the trusted build directories: remove them "
                          "or move them out of the clone" % MAX_LISTED)
    return out


def index_entries(root):
    """{path: mode} of the index."""
    out = {}
    for rec in split0(git(root, "ls-files", "-z", "--cached", "--stage")):
        meta, path = rec.split("\t", 1)
        out[path] = meta.split()[0]
    return out


def listed_paths(root, rev):
    """Paths in `rev`'s tree, in the index, and every path on disk outside the trusted build directories.
    A gitlink (a submodule or an added embedded repository) anywhere is BLOCKED: its contents are another
    repository's and cannot be checked here."""
    tree, index = tree_entries(root, rev), index_entries(root)
    head = tree if rev == "HEAD" else tree_entries(root, "HEAD")
    gitlinks = sorted({p for t in (tree, head) for p, (m, _o) in t.items() if m == "160000"}
                      | {p for p, m in index.items() if m == "160000"})
    if gitlinks:
        raise QcError("BLOCKED", "gitlinks (submodules or embedded repositories) %s: their contents cannot be "
                      "checked; remove them from the index and the tree" % gitlinks[:5])
    tracked = set(tree) | set(index)
    return tracked | (disk_paths(root) - (LOCAL_ONLY - tracked))


def disk_entry(root, rel, fmt):
    """(mode, oid) of the file at `rel` as git would store it without filters; None if absent."""
    p = os.path.join(root, rel)
    try:
        st = os.lstat(p)
    except (FileNotFoundError, NotADirectoryError):
        return None
    if stat.S_ISLNK(st.st_mode):
        data, mode = os.readlink(p).encode(), "120000"
    elif stat.S_ISREG(st.st_mode):
        with open(p, "rb") as f:
            data = f.read()
        mode = "100755" if st.st_mode & stat.S_IXUSR else "100644"
    elif stat.S_ISDIR(st.st_mode):
        return ("040000", "dir")  # a listed path that is now a directory: its files are listed themselves
    else:
        return ("0", "special")
    h = hashlib.sha256() if fmt == "sha256" else hashlib.sha1()
    h.update(b"blob %d\0" % len(data) + data)
    return (mode, h.hexdigest())


def unlisted_target(root, real_root, rel, listed):
    """The target of the link `rel` if its contents are not fingerprinted at a path of their own: a file
    out of the clone, in its .git or in a trusted build directory. BLOCKED if such a target is a
    directory. None for a link to a listed file, a listed directory's contents, or nothing."""
    target = os.path.realpath(os.path.join(root, rel))
    where = "outside the clone"
    if (target + os.sep).startswith(real_root + os.sep):
        inside = os.path.relpath(target, real_root)
        if inside == ".git" or inside.startswith(".git/"):
            where = "in the clone's .git"
        elif in_trusted_dir(inside):
            where = "in a trusted build directory"
        elif os.path.isdir(target) or not os.path.exists(target) or inside in listed:
            return None  # a listed file, or a directory whose files are walked and listed at their own paths
    elif not os.path.exists(target):
        return None
    if os.path.isdir(target):
        raise QcError("BLOCKED", "%s links to a directory %s (%s): its contents cannot be checked; copy them "
                      "in or remove the link" % (rel, where, target))
    return target


GIT_STATE_FILES = ("config", "config.worktree", "info/attributes")


def fingerprint(root):
    """HEAD and the bytes of every listed path as they are on disk."""
    fmt = object_format(root)
    head = git(root, "rev-parse", "HEAD").strip()
    h = hashlib.sha256(head.encode())
    real_root = os.path.realpath(root)
    listed = listed_paths(root, "HEAD") | LOCAL_ONLY
    for rel in sorted(listed):
        e = disk_entry(root, rel, fmt)
        h.update(rel.encode() + b"\0" + ("%s %s" % e if e else "-").encode() + b"\n")
        if e and e[0] == "120000":
            # A link to contents not listed elsewhere: what it points at is part of what ran.
            target = unlisted_target(root, real_root, rel, listed)
            if target:
                h.update(b"->" + (sha256_file(target).encode() if os.path.isfile(target) else b"-"))
    # The git state a criterion may read (`git show :path`, a diff driver in the config, attributes) is part
    # of what ran: the index entries (not their stat data), the clone's config and info/attributes.
    h.update(b"\0index\0" + git(root, "ls-files", "-z", "--stage", binary=True))
    for name in GIT_STATE_FILES:
        p = git(root, "rev-parse", "--git-path", name).strip()
        p = p if os.path.isabs(p) else os.path.join(root, p)
        h.update(("\0%s\0%s" % (name, sha256_file(p) if os.path.isfile(p) else "-")).encode())
    return h.hexdigest()


def local_settings_hash(root):
    """sha256 of each LOCAL_ONLY file, or None where absent."""
    return {rel: sha256_file(os.path.join(root, rel)) if os.path.isfile(os.path.join(root, rel)) else None
            for rel in sorted(LOCAL_ONLY)}


def changed_paths(root, base):
    """Paths whose bytes or mode on disk differ from `base`'s tree (a deleted or moved file at its old path)."""
    fmt = object_format(root)
    base_tree = tree_entries(root, base)
    changed = []
    real_root = os.path.realpath(root)
    listed = listed_paths(root, base)
    for rel in listed:
        e = disk_entry(root, rel, fmt)
        if e and e[0] == "120000":
            unlisted_target(root, real_root, rel, listed)
        if e != base_tree.get(rel):
            changed.append(rel)
    return sorted(changed)


def blob_text(root, oid):
    return git(root, "cat-file", "blob", oid, binary=True).decode("utf-8", "replace")


def file_text(root, rel):
    p = os.path.join(root, rel)
    if os.path.islink(p) or not os.path.isfile(p):
        return ""
    with open(p, "rb") as f:
        return f.read().decode("utf-8", "replace")


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


def added_lines(root, base, paths=None):
    """(path, line) for every line the tree on disk adds over `base`, new files included."""
    base_tree = tree_entries(root, base)
    for rel in (changed_paths(root, base) if paths is None else paths):
        old = blob_text(root, base_tree[rel][1]).splitlines() if rel in base_tree and \
            base_tree[rel][0] != "160000" else []
        new = file_text(root, rel).splitlines()
        for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
            if tag in ("insert", "replace"):
                for line in new[j1:j2]:
                    yield rel, line


def recorded_tree(root, sid, n):
    """The tree object of the tree on disk, kept by refs/arcium-qc/<id>/run-<n> (kept by gc; not pushed
    by `git push` or `--all`, but `git push --mirror` would publish it, untracked files included), or the
    reason it could not be written."""
    try:
        tree = write_tree(root, listed_paths(root, "HEAD"))
        git(root, "update-ref", "refs/arcium-qc/%s/run-%d" % (sid, n), tree)
        return tree
    except (QcError, OSError) as e:
        return "not written: %s" % e


def write_tree(root, paths):
    """A git tree object of the tree on disk (the given listed paths), for reproducing a run.
    Writes blobs and a tree into the object database only; the index and the working tree are untouched."""
    fmt = object_format(root)
    entries, batch, single = [], [], []
    for rel in sorted(paths):
        e = disk_entry(root, rel, fmt)
        if e is None or e[0] in ("040000", "0"):
            continue
        entries.append((rel, e))
        (single if e[0] == "120000" or "\n" in rel else batch).append(rel)
    stored = {}
    if batch:
        out = git(root, "hash-object", "-w", "--no-filters", "--stdin-paths",
                  stdin="".join(os.path.join(root, r) + "\n" for r in batch).encode()).split()
        stored.update(zip(batch, out))
    for rel in single:
        p = os.path.join(root, rel)
        data = os.readlink(p).encode() if os.path.islink(p) else open(p, "rb").read()
        stored[rel] = git(root, "hash-object", "-w", "--no-filters", "--stdin", stdin=data).strip()
    lines = []
    for rel, (mode, oid) in entries:
        if stored.get(rel) != oid:
            raise QcError("BLOCKED", "git stored %s as %s, expected %s" % (rel, stored.get(rel), oid))
        lines.append("%s %s\t%s" % (mode, oid, rel))
    index = os.path.join(state_dir(root), "tree-index.%d" % os.getpid())
    try:
        git(root, "update-index", "-z", "--index-info", stdin="".join(x + "\0" for x in lines).encode(),
            env={"GIT_INDEX_FILE": index})
        return git(root, "write-tree", env={"GIT_INDEX_FILE": index}).strip()
    finally:
        if os.path.exists(index):
            os.remove(index)


# Rust source taken from a path literal (#[path], include!, include_str!, include_bytes!): a build-output
# directory is never a source directory, and its contents are not fingerprinted.
RUST_INCLUDE_RE = re.compile(r'(?:#\s*!?\[\s*path\s*=|\binclude(?:_str|_bytes)?!\s*\()\s*r?#*"([^"]*)"')
BUILD_DIR_COMPONENT_RE = re.compile(r"(^|/)(%s)(/|$)" % "|".join(
    sorted({re.escape(d.rsplit("/", 1)[-1]) for d in TRUSTED_BUILD_DIRS})))


def content_flags(root, base, paths=None):
    """Added lines that CLAUDE.md forbids outright."""
    flags = []
    for cur, add in added_lines(root, base, paths):
        if cur.startswith(".github/") and re.search(r"continue-on-error:\s*true|\|\|\s*true\b", add):
            flags.append("CI_MASKED_GATE_CANDIDATE %s: %s" % (cur, add.strip()[:120]))
        if cur.startswith("arcium-psi/") and re.search(r"XChaCha|chacha20|Aes(Gcm|256)|aes-gcm", add, re.I):
            flags.append("CRYPTO_LAYERING message AEAD in PSI code %s" % cur)
        if (cur.startswith("crates/core-crypto/src/ratchet") or cur.startswith("crates/core-protocol/")) \
                and re.search(r"RescueCipher|rescue::", add):
            flags.append("CRYPTO_LAYERING RescueCipher on the message path %s" % cur)
        if cur.endswith(".rs") and any(BUILD_DIR_COMPONENT_RE.search(lit) for lit in RUST_INCLUDE_RE.findall(add)):
            flags.append("BUILD_OUTPUT_INCLUDE source compiled from a build-output directory %s: %s"
                         % (cur, add.strip()[:120]))
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
        "flags": content_flags(root, base, paths),
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
        # The program by its name, wherever it lives (/usr/bin/python3, ~/.cargo/bin/cargo).
        runner = TEST_RUNNER_RE.search(" ".join([os.path.basename(argv[0])] + argv[1:]))
        if runner and not c.get("must_match"):
            errs.append("%s: a test run needs must_match proving tests ran (a filter matching nothing exits 0)"
                        % where)
        if runner and c.get("expect_exit", 0) != 0:
            errs.append("%s: a test run must expect_exit 0 (a non-zero expectation passes on failing tests)"
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
    st = read_record(p, "the state of %s" % sid)
    if not verify_sig(root, st):
        raise QcError("BLOCKED", "state of %s fails its integrity check (edited or forged)" % sid)
    return st


def save_state(root, sid, st):
    os.makedirs(os.path.dirname(state_path(root, sid)), mode=0o700, exist_ok=True)
    write_json(state_path(root, sid), sign(root, st))


def run_dir(root, sid):
    if not ID_RE.match(sid or ""):
        raise QcError("BLOCKED", "invalid spec id %r" % sid)
    d = os.path.dirname(state_path(root, sid))
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


@contextlib.contextmanager
def spec_lock(root, sid):
    """One run, lock or review-record per spec at a time; never waits. The lock is on the spec's
    record directory itself, which cannot be deleted while it holds the state."""
    fd = os.open(run_dir(root, sid), os.O_RDONLY)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise QcError("NOT_VERIFIED", "another qc.py run or review-record for %s is in progress; "
                          "wait for it to finish" % sid)
        yield
    finally:
        os.close(fd)  # releases the lock


def lock_held(root, sid):
    """Whether a run (or record) for `sid` holds the spec's lock right now."""
    fd = os.open(run_dir(root, sid), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return False
    except BlockingIOError:
        return True
    finally:
        os.close(fd)


RECORD_RE = re.compile(r"^(run|review)-([0-9]+)\.json$")


def record_ok(root, path, kind, n, spec_sha):
    """The signed record at `path` if it is this spec's `kind` record number `n`; None if absent."""
    if not os.path.exists(path):
        return None
    rec = read_record(path, os.path.basename(path))
    if not verify_sig(root, rec) or rec.get("kind") != kind or rec.get("n") != n or \
            rec.get("spec_sha256") != spec_sha:
        raise QcError("BLOCKED", "%s fails its integrity check (edited or fabricated)" % os.path.basename(path))
    return rec


def settle(root, sid, st, spec_sha):
    """A copy of `st` with what a dead process left in flight resolved. A run whose signed record was
    written is adopted (a FAILED one counts); a run that left none is INTERRUPTED and also counts as
    a failed round, so killing a run never saves budget. A review whose record was written is adopted
    (a blocking one counts); one that left none is dropped."""
    st = json.loads(json.dumps(st))
    d = run_dir(root, sid)
    inf = st.pop("inflight", None)
    if inf:
        n = inf["n"]
        rec = record_ok(root, os.path.join(d, "run-%d.json" % n), "run", n, spec_sha)
        if rec:
            st["runs"].append({"n": n, "outcome": rec["outcome"], "sha256": sha256_file(os.path.join(d, "run-%d.json" % n))})
            st["failed_runs"] += rec["outcome"] == "FAILED"
        else:
            st["runs"].append({"n": n, "outcome": "INTERRUPTED", "sha256": None})
            st["failed_runs"] += 1
    rinf = st.pop("review_inflight", None)
    if rinf:
        n = rinf["n"]
        path = os.path.join(d, "review-%d.json" % n)
        rec = record_ok(root, path, "review", n, spec_sha)
        if rec:
            st.setdefault("reviews", []).append({"n": n, "skill": rec["skill"], "sha256": sha256_file(path)})
            st["failed_runs"] += bool(rec["blocking"])
    return st


def check_ledger(root, sid, st):
    """Every record on disk is in the ledger: a state rolled back to an older signed copy, or deleted
    and locked again, leaves later records behind and is BLOCKED. (Deleting the records too is not
    detectable locally.)"""
    runs = {r["n"] for r in st["runs"]} | ({st["inflight"]["n"]} if st.get("inflight") else set())
    reviews = {r["n"] for r in st.get("reviews", [])} | (
        {st["review_inflight"]["n"]} if st.get("review_inflight") else set())
    for name in os.listdir(run_dir(root, sid)):
        m = RECORD_RE.match(name)
        if m and int(m.group(2)) not in (runs if m.group(1) == "run" else reviews):
            raise QcError("BLOCKED", "%s is not in the state ledger: the state was rolled back or replaced" % name)


def preconditions(root, sid, check_lock=True):
    """Spec, lock, tool integrity, owner gates, budget. Raises QcError. With `check_lock`, work in flight
    under a live lock stays in flight (the caller reports it); otherwise it is settled in the copy
    returned, which a caller holding the lock saves."""
    spec, spec_sha = load_spec(root, sid)
    st = load_state(root, sid)
    if st is None:
        raise QcError("BLOCKED", "spec %s is not locked: lock it before implementing (qc.py lock)" % sid)
    check_ledger(root, sid, st)
    if st["spec_sha256"] != spec_sha:
        raise QcError("BLOCKED", "spec %s changed after it was locked: criteria cannot move mid-task" % sid)
    if st["tool_sha256"] != tool_hash():
        raise QcError("BLOCKED", "the QC tool (qc.py/hooks.py) changed after the spec was locked")
    if (st.get("inflight") or st.get("review_inflight")) and not (check_lock and lock_held(root, sid)):
        st = settle(root, sid, st, spec_sha)
    if subprocess.run(["git", *GIT_OPTS, "-C", root, "merge-base", "--is-ancestor", spec["base"], "HEAD"],
                      capture_output=True, env=git_env()).returncode != 0:
        raise QcError("BLOCKED", "base %s is not an ancestor of HEAD" % spec["base"][:12])
    if "local_settings" in st and local_settings_hash(root) != st["local_settings"]:
        # Claude Code's local settings carry permissions, environment and hooks for the session that
        # runs the loop: not part of the change, but not to be changed under it either.
        raise QcError("ESCALATE_TO_OWNER", "%s changed after the spec was locked (AGENT_CONTROL): ask the Owner"
                      % ", ".join(sorted(LOCAL_ONLY)))
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


def toolchain(root, argv, env):
    """What a criterion ran besides the tree: the program and the Cargo configuration outside it."""
    def entry(path):
        try:
            return {"path": path, "sha256": sha256_file(path)}
        except OSError as e:
            return {"path": path, "error": str(e)}
    exe = shutil.which(argv[0], path=env.get("PATH"))
    above = []
    d = os.path.dirname(os.path.realpath(root))
    cargo_home = os.path.realpath(env.get("CARGO_HOME") or os.path.join(os.path.expanduser("~"), ".cargo"))
    while True:
        for name in ("config", "config.toml"):
            p = os.path.join(d, ".cargo", name)
            if os.path.isfile(p) and os.path.realpath(os.path.dirname(p)) != cargo_home:
                above.append(entry(p))
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    home = [entry(os.path.join(cargo_home, n)) for n in ("config", "config.toml")
            if os.path.isfile(os.path.join(cargo_home, n))]
    return {"program": entry(os.path.realpath(exe)) if exe else None, "cargo_config_above_root": above,
            "cargo_home_config": home,
            "env": {k: v for k, v in sorted(env.items()) if re.match(r"^(CARGO_|RUSTC|RUSTFLAGS|RUSTDOC)", k)}}


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
    res["toolchain"] = toolchain(root, argv, env)
    if os.path.basename(argv[0]).startswith("cargo") and res["toolchain"]["cargo_config_above_root"]:
        res.update(status="NOT_VERIFIED", reason="a Cargo configuration outside the repository (%s) can change "
                   "what cargo runs; it is not part of the diff or the review"
                   % res["toolchain"]["cargo_config_above_root"][0]["path"])
        return res
    runners = sorted(k for k in env if re.match(r"^CARGO_TARGET_[A-Z0-9_]+_RUNNER$", k))
    if os.path.basename(argv[0]).startswith("cargo") and runners:
        res.update(status="NOT_VERIFIED", reason="%s replaces the program cargo runs for tests; unset it"
                   % runners[0])
        return res
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
    with spec_lock(root, sid):
        return _run(root, sid)


def _run(root, sid):
    raw = load_state(root, sid)
    spec, spec_sha, st, cls = preconditions(root, sid, check_lock=False)
    if raw and (raw.get("inflight") or raw.get("review_inflight")):
        save_state(root, sid, st)  # the lock is ours: what the dead process left is settled for good
    if len(st["runs"]) >= MAX_RUNS:
        raise QcError("ESCALATE_TO_OWNER", "%d runs recorded: the run cap is reached" % len(st["runs"]))
    fp_before = fingerprint(root)
    st["inflight"] = {"n": len(st["runs"]) + 1, "time": int(time.time()), "fingerprint": fp_before}
    save_state(root, sid, st)
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
                     "tree": recorded_tree(root, sid, len(st["runs"]) + 1),
                     "classification": cls, "results": results, "outcome": outcome, "why": why})
    ev_path = os.path.join(os.path.dirname(state_path(root, sid)), "run-%d.json" % n)
    write_json(ev_path, ev, exclusive=True)
    crash_point("run-recorded")
    st["runs"].append({"n": n, "outcome": outcome, "sha256": sha256_file(ev_path)})
    del st["inflight"]
    if outcome == "FAILED":
        st["failed_runs"] += 1
    save_state(root, sid, st)
    return _verdict_unlocked(root, sid)


# ── Reviews ──────────────────────────────────────────────────────────────────

REVIEW_BLOCKS = {
    "engineering-code-review": ("KARPATHY_REVIEW_RESULT", "KARPATHY_REVIEW_END"),
    "arcium-security-review": ("ARCIUM_SECURITY_REVIEW", "ARCIUM_SECURITY_REVIEW_END"),
}


def review_block(skill, text):
    """The text between the skill's start and end lines: only it counts, never text around it."""
    start, end = REVIEW_BLOCKS[skill]
    m = re.search(re.escape(start) + r"\n(.*?)\n" + re.escape(end), text, re.S)
    if not m:
        raise QcError("NOT_VERIFIED", "no %s ... %s block in the review" % (start, end))
    return m.group(1)


def parse_review(skill, text):
    block = review_block(skill, text)
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
    with spec_lock(root, sid):
        return _review_record(root, sid, skill, text)


def _review_record(root, sid, skill, text):
    raw = load_state(root, sid)
    spec, spec_sha, st, cls = preconditions(root, sid, check_lock=False)
    if raw and (raw.get("inflight") or raw.get("review_inflight")):
        save_state(root, sid, st)
    parsed = parse_review(skill, text)
    block = review_block(skill, text)
    target = re.search(r"^target:\s*(\S+)", block, re.M)
    if not target or not target.group(1).startswith(spec["base"]):
        raise QcError("NOT_VERIFIED", "review target must start with the spec base %s" % spec["base"])
    missing = [p for p in cls["paths"]
               if not re.search(r"(?<![\w./-])" + re.escape(p) + r"(?!\.?[\w/-])", block)]
    if missing:
        raise QcError("NOT_VERIFIED", "review does not name every changed path; missing %s" % missing[:10])
    # The review is of the tree the criteria passed on: the reviewer quotes its
    # fingerprint (qc.py status) before reading, and nothing changed since.
    fp = fingerprint(root)
    quoted = re.search(r"^qc_fingerprint:\s*([0-9a-f]{64})\s*$", block, re.M)
    if not quoted:
        raise QcError("NOT_VERIFIED", "review block lacks the line qc_fingerprint: <hex> (qc.py status %s)" % sid)
    if quoted.group(1) != fp:
        raise QcError("NOT_VERIFIED", "the review quotes another tree than the current one; review it again")
    last = st["runs"][-1] if st["runs"] else None
    if not last or last["outcome"] != "PASS":
        raise QcError("NOT_VERIFIED", "no completed passing run for this tree: run the criteria before the review")
    ev = load_record(root, sid, "run-%d.json" % last["n"], last["sha256"])
    if ev["fingerprint"] != fp:
        raise QcError("NOT_VERIFIED", "the tree changed after run %d passed: run the criteria again" % last["n"])
    n = len(st.get("reviews", [])) + 1
    rec = sign(root, {"kind": "review", "spec_id": sid, "spec_sha256": spec_sha, "skill": skill, "n": n,
                      "time": int(time.time()), "fingerprint": fp, "run_n": last["n"], "text": text, **parsed})
    path = os.path.join(os.path.dirname(state_path(root, sid)), "review-%d.json" % n)
    st["review_inflight"] = {"n": n}
    save_state(root, sid, st)
    write_json(path, rec, exclusive=True)
    crash_point("review-recorded")
    st.setdefault("reviews", []).append({"n": n, "skill": skill, "sha256": sha256_file(path)})
    del st["review_inflight"]
    if parsed["blocking"]:
        st["failed_runs"] += 1
    save_state(root, sid, st)
    return _verdict_unlocked(root, sid)


# ── Verdict ──────────────────────────────────────────────────────────────────

def load_record(root, sid, name, expect_sha):
    path = os.path.join(os.path.dirname(state_path(root, sid)), name)
    if not os.path.exists(path) or sha256_file(path) != expect_sha:
        raise QcError("BLOCKED", "%s is missing or differs from the state ledger" % name)
    rec = read_record(path, name)
    if not verify_sig(root, rec):
        raise QcError("BLOCKED", "%s fails its integrity check (edited or fabricated)" % name)
    return rec


def verdict(root, sid):
    return _guarded(_verdict, root, sid, True)


def _verdict_unlocked(root, sid):
    """The verdict from inside a command that holds the spec's lock itself."""
    return _guarded(_verdict, root, sid, False)


def _guarded(fn, root, sid, check_lock):
    try:
        return fn(root, sid, check_lock)
    except QcError as e:
        return e.state, e.reason
    except Exception as e:  # noqa: BLE001 - an internal error is never a pass
        return "BLOCKED", "internal error in qc.py (%s: %s): fix the tool or its state" % (type(e).__name__, e)


def _verdict(root, sid, check_lock=True):
    spec, spec_sha, st, cls = preconditions(root, sid, check_lock)
    state, why, needs_run = _assess(root, sid, spec, spec_sha, st, cls, check_lock)
    if needs_run and len(st["runs"]) >= MAX_RUNS:
        # Progress needs another run and none is allowed: the Owner decides.
        return "ESCALATE_TO_OWNER", "%d runs recorded, the run cap is reached; last state %s: %s" % (
            len(st["runs"]), state, why)
    return state, why


def _assess(root, sid, spec, spec_sha, st, cls, check_lock):
    """(state, reason, whether only a new run could change it)."""
    left = 1 + spec.get("max_repair_rounds", MAX_REPAIR_ROUNDS) - st["failed_runs"]
    # Work in flight is still here only while its process holds the lock (preconditions settles the rest).
    if st.get("inflight"):
        return "NOT_VERIFIED", "run %d is in progress; wait for it" % st["inflight"]["n"], False
    if st.get("review_inflight"):
        return "NOT_VERIFIED", "a review is being recorded; wait for it", False
    if not st["runs"]:
        return "NOT_VERIFIED", "no evidence: run the criteria (qc.py run %s)" % sid, True
    last = st["runs"][-1]
    if last["outcome"] == "INTERRUPTED":
        return "NOT_VERIFIED", "run %d was interrupted before it finished; run again" % last["n"], True
    ev = load_record(root, sid, "run-%d.json" % last["n"], last["sha256"])
    if ev["spec_sha256"] != spec_sha:
        return "BLOCKED", "the evidence is for another version of the spec", False
    fp = fingerprint(root)
    if ev["fingerprint"] != fp:
        return "NOT_VERIFIED", "stale evidence: the tree changed after run %d; run again" % ev["n"], True
    if ev["outcome"] == "FAILED":
        return "FAILED", "%s; %d repair round(s) left" % (ev["why"], left), True
    if ev["outcome"] != "PASS":
        return "NOT_VERIFIED", ev["why"], True
    pending, incomplete = [], []
    for skill in cls["required_reviews"]:
        recs = [load_record(root, sid, "review-%d.json" % r["n"], r["sha256"])
                for r in st.get("reviews", []) if r["skill"] == skill]
        current = [r for r in recs if r["fingerprint"] == fp and r.get("spec_sha256") == spec_sha]
        if not current:
            pending.append(skill + (" (stale)" if recs else ""))
            continue
        # A later record never erases a blocking one for the same tree.
        blocking = [b for r in current for b in r["blocking"]]
        if blocking:
            return "FAILED", "%s found %s; %d repair round(s) left" % (skill, blocking, left), True
        if not current[-1]["complete"]:
            incomplete.append(skill)
    if pending or incomplete:
        return "NOT_VERIFIED", "criteria passed; review %s%s" % (
            ("pending: %s" % pending) if pending else "",
            (" incomplete: %s" % incomplete) if incomplete else ""), False
    granted = sorted(set(cls["owner_gated"]) & set(spec.get("owner_authorizes", [])))
    return "VERIFIED", "run %d passed every criterion on this tree; reviews recorded: %s%s" % (
        ev["n"], cls["required_reviews"] or "none required",
        ("; owner authority self-declared in the spec for %s: confirm it against the Owner's instruction"
         % granted) if granted else ""), False


# ── Activation (for the optional hooks) ─────────────────────────────────────

def active_path(root):
    return os.path.join(state_dir(root), "active.json")


def activation(root):
    """(spec id or None, whether an activation record exists that is unreadable or fails its integrity
    check). An expired activation is simply inactive. Creates nothing."""
    p = os.path.join(qc_dir(root), "active.json")
    if not os.path.exists(p):
        return None, False
    try:
        a = read_json(p)
        if not isinstance(a, dict) or not verify_sig(root, a):
            return None, True
    except (OSError, ValueError, TypeError, KeyError):
        return None, True
    if time.time() > a.get("expires", 0):
        return None, False
    return a.get("spec_id"), False


def active_loop(root):
    """The active spec id, or None. Creates nothing."""
    return activation(root)[0]


def cmd_status(root, sid):
    """Read-only progress report for the Owner and for resuming a loop."""
    spec, _ = load_spec(root, sid)
    st = load_state(root, sid)
    if st is None:
        raise QcError("BLOCKED", "spec %s is not locked" % sid)
    limit = 1 + spec.get("max_repair_rounds", MAX_REPAIR_ROUNDS)
    reviews = []
    fp = fingerprint(root)
    for r in st.get("reviews", []):
        try:
            rec = load_record(root, sid, "review-%d.json" % r["n"], r["sha256"])
        except QcError as e:
            reviews.append({"n": r["n"], "skill": r["skill"], "error": e.reason})
            continue
        reviews.append({"n": r["n"], "skill": r["skill"], "run_n": rec.get("run_n"), "complete": rec["complete"],
                        "blocking": rec["blocking"], "for_current_tree": rec["fingerprint"] == fp})
    state, why = verdict(root, sid)
    return {
        "spec_id": sid, "base": spec["base"], "locked_at": st["locked_at"], "fingerprint": fp,
        "runs": [{"n": r["n"], "outcome": r["outcome"]} for r in st["runs"]],
        "inflight": st.get("inflight"), "review_inflight": st.get("review_inflight"),
        "failed_runs": st["failed_runs"],
        "repair_rounds_left": max(0, min(limit - 1, limit - st["failed_runs"])),
        "runs_left": max(0, MAX_RUNS - len(st["runs"])), "reviews": reviews,
        "verdict": {"state": state, "why": why},
    }


# ── CLI ──────────────────────────────────────────────────────────────────────

def cmd_lock(root, sid):
    with spec_lock(root, sid):
        return _lock(root, sid)


def _lock(root, sid):
    spec, spec_sha = load_spec(root, sid)
    if load_state(root, sid) is not None:
        raise QcError("BLOCKED", "spec %s is already locked; a new task needs a new id" % sid)
    left = sorted(f for f in os.listdir(run_dir(root, sid)) if RECORD_RE.match(f))
    if left:
        raise QcError("BLOCKED", "spec %s has records from an earlier lock (%s): its state was deleted; "
                      "a new task needs a new id" % (sid, ", ".join(left[:5])))
    head = git(root, "rev-parse", "HEAD").strip()
    if head != spec["base"]:
        raise QcError("BLOCKED", "lock requires HEAD == base (%s); HEAD is %s" % (spec["base"][:12], head[:12]))
    dirty = changed_paths(root, head)
    if dirty:
        raise QcError("BLOCKED", "lock requires a clean tree (the bytes on disk equal HEAD): criteria are fixed "
                      "before implementation; changed: %s" % dirty[:10])
    save_state(root, sid, {"spec_id": sid, "spec_sha256": spec_sha, "tool_sha256": tool_hash(),
                           "local_settings": local_settings_hash(root),
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
            # Each trusted build directory is one the repository's own tracked .gitignore files exclude.
            untrusted = [d for d in TRUSTED_BUILD_DIRS
                         if not os.path.isdir(os.path.join(root, os.path.dirname(d) or "."))
                         or subprocess.run(["git", *GIT_OPTS, "check-ignore", "-q", "--no-index", d + "/"],
                                           cwd=root, env=git_env(), capture_output=True).returncode != 0]
            print(json.dumps({"stale_rules": missing, "untrusted_build_dirs": untrusted}))
            return 1 if missing or untrusted else 0
        if cmd == "activate":
            sid = args[0]
            load_spec(root, sid)
            cur, invalid = activation(root)
            if invalid:
                raise QcError("BLOCKED", "the activation record is unreadable or fails its integrity check: "
                              "only the Owner ends it (delete %s)" % active_path(root))
            cur_state = verdict(root, cur)[0] if cur is not None and cur != sid else None
            if cur_state not in (None, "VERIFIED"):
                # Switching loops would end this one without its report (or hide its escalation).
                raise QcError(cur_state, "loop %s is %s: it is replaced only once VERIFIED; otherwise the Owner "
                              "ends it (delete %s), or it expires" % (cur, cur_state, active_path(root)))
            write_json(active_path(root), sign(root, {"spec_id": sid, "expires": int(time.time()) + ACTIVE_TTL}))
            print("QC loop %s active for %dh (hooks, if enabled, now apply)" % (sid, ACTIVE_TTL // 3600))
            return 0
        if cmd == "deactivate":
            sid, invalid = activation(root)
            cur_state = "BLOCKED" if invalid else verdict(root, sid)[0] if sid is not None else None
            if cur_state not in (None, "VERIFIED"):
                # The guards stay armed until the loop is VERIFIED, so a stop or a commit before that cannot
                # follow an early deactivation; the Owner ends it by deleting active.json, or it expires.
                raise QcError(cur_state, "loop %s is %s: it is deactivated only once VERIFIED; otherwise only "
                              "the Owner ends it (delete %s), or it expires" % (sid, cur_state, active_path(root)))
            if os.path.exists(active_path(root)):
                os.remove(active_path(root))
            print("no QC loop active")
            return 0
        if cmd == "status":
            print(json.dumps(cmd_status(root, args[0]), indent=1))
            return 0
        if cmd == "evidence":
            st = load_state(root, args[0])
            if not st or not st["runs"]:
                raise QcError("NOT_VERIFIED", "no evidence for %s" % args[0])
            last = st["runs"][-1]
            n = last["n"]
            if last["outcome"] == "INTERRUPTED":
                raise QcError("NOT_VERIFIED", "run %d was interrupted: it left no evidence" % n)
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
    except Exception as e:  # noqa: BLE001 - an internal error is never a pass
        state, why = "BLOCKED", "internal error in qc.py (%s: %s)" % (type(e).__name__, e)
    print("QC_STATE: %s | %s" % (state, why))
    return EXIT[state]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
