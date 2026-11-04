#!/usr/bin/env python3
"""Optional QC guards for Claude Code hooks. Candidates, disabled by default.

They run only if an Owner adds .claude/qc/hooks.candidate.json to
.claude/settings.local.json, and even then do nothing unless a QC loop was
activated in this clone (qc.py activate <id>, which expires after 8 hours).

  stop             Stop: refuses a final message that claims
                   "QC_STATE: VERIFIED" while qc.py's verdict is something
                   else, or that does not report an ESCALATE_TO_OWNER (no
                   QC_STATE line at all counts as hiding it). A verdict that
                   cannot be computed is BLOCKED, so an error inside qc.py's
                   verdict never lets a VERIFIED claim through. Never blocks when
                   stop_hook_active is true, so it adds at most one turn; a
                   claim still false then is shown to the person as a warning.
  task-completed   TaskCompleted: a task whose subject carries "[qc]" cannot be
                   marked completed unless the verdict is VERIFIED.
  pre-tool         PreToolUse: denies owner-only operations (commit, push,
                   merge, PR writes, workflow dispatch, deploy) and edits of the
                   QC tool, its evidence under .git/, agent settings and
                   CLAUDE.md while the loop is active. `qc.py review-record`
                   with a quoted heredoc is let through as data. Pattern
                   matching on commands is a guard against mistakes, not a
                   sandbox.

They only ever deny or stay silent: no output here grants a permission.
The loop is looked up in the clone of the payload's cwd, of
$CLAUDE_PROJECT_DIR and of this file. With no loop active anywhere, nothing
is checked. While a loop is active, a guard that cannot decide fails
closed: an internal error or the internal deadline (below the hook timeout)
denies the tool call, blocks a stop once, or refuses the task; an
activation record that is unreadable or fails its integrity check counts as
active. Hook input that is empty, cannot be read within READ_DEADLINE, is
not a usable JSON object or is larger than MAX_INPUT is not parsed: with a
loop active the step is refused, with none it is ignored. If the guard
cannot even find out whether a loop is active (its deadline, git or qc.py
failing in that clone, any internal error), an activation record found on
the file system alone counts as active, expired or not; a .git file that
cannot be read or decoded shows none. The Owner releases a loop by deleting
active.json. qc.py is loaded from
its source text, never from a cached .pyc; run this file with `python3 -I -B`
so nothing next to it shadows the standard library. Claude Code's own
permission mode still applies.
"""

import io
import json
import os
import re
import shlex
import signal
import sys
import types

# No __pycache__ in the working tree: it would change the tree fingerprint.
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))


def load_qc():
    """qc.py compiled from its source: a planted __pycache__/qc.*.pyc is never imported."""
    path = os.path.join(HERE, "qc.py")
    mod = types.ModuleType("qc")
    mod.__file__ = path
    with open(path, "rb") as f:
        code = compile(f.read(), path, "exec", dont_inherit=True)
    sys.modules["qc"] = mod
    exec(code, mod.__dict__)  # noqa: S102 - the QC tool's own source, next to this file
    return mod


try:
    qc = load_qc()
except Exception:  # noqa: BLE001 - a QC tool that does not load: discovery then fails, see roots()
    qc = None
# Seconds a hook may spend before it fails closed; each stays below its timeout in hooks.candidate.json.
DEADLINE = {"stop": 40, "task-completed": 40, "pre-tool": 10}
# Seconds the hook waits for its input before treating it as unusable (before DEADLINE starts).
READ_DEADLINE = 5

CLAIM_RE = re.compile(r"QC_STATE:\s*(VERIFIED|FAILED|NOT_VERIFIED|BLOCKED|ESCALATE_TO_OWNER)\b")

GIT_OWNER_ONLY = re.compile(
    r"(^|[\s;&|(`$/\\\"'])git[\"']?\s+(?:-C\s+\S+\s+|-c\s+\S+\s+|--\S+\s+)*"
    r"(commit|push|merge(?!-)|rebase|tag(?!\s+(-l|--list)\b)|cherry-pick|am|revert|update-ref|filter-branch|"
    r"filter-repo|replace)\b")
OTHER_OWNER_ONLY = re.compile(
    r"(^|[\s;&|(`$/\\\"'])(gh\s+(pr\s+(?!(view|list|diff|checks|status)\b)|workflow\s+(run|enable|disable)\b|"
    r"release\s+(create|delete|edit|upload)\b|api\b|repo\s+(create|delete|edit|fork|rename)\b|"
    r"run\s+(rerun|cancel|delete)\b)|"
    r"(anchor|arcium)\s+deploy\b|solana\s+(airdrop|program\s+deploy|deploy)\b)")
MCP_WRITE = re.compile(
    r"^mcp__github__(merge_|create_|update_|delete_|push_|fork_|enable_|disable_|add_|resolve_|unresolve_|"
    r"request_|actions_run_trigger|issue_write|sub_issue_write|pull_request_review_write)")
PROTECTED = re.compile(r"(^|/)(CLAUDE[^/]*\.md|AGENTS\.md|\.mcp\.json|\.githooks/|\.git/|\.pi/|"
                       r"\.claude/(settings[^/]*\.json|qc/|hooks/|agents/|skills/|commands/))")
BASH_WRITES_PROTECTED = re.compile(
    r"((?<![0-9&])>(?!&)|\btee\b|\bsed\s+-i|\bmv\b|\bcp\b|\brm\b|\bchmod\b|\btruncate\b|\binstall\b|"
    r"\bln\b|\bdd\b|\brsync\b|\bunlink\b|"
    r"\bpython3?\s+-c\b|\bperl\s+-\w*[pie]|\bgit\b.*\b(checkout|restore|reset|clean|stash|apply|switch)\b).*"
    r"(%(targets)s)|\bfind\b.*(%(targets)s).*\s-(delete|exec|execdir|ok|okdir|fprint)\b" % {"targets":
    r"CLAUDE[^/\s]*\.md|AGENTS\.md|\.mcp\.json|\.githooks/|\.git/(info|hooks|config)|\.pi/|"
    r"\.claude/(settings|qc|hooks|agents|skills|commands)|arcium-qc"})
# git subcommands that are owner-only, and the global options that take a separate argument.
GIT_OWNER_SUBCOMMANDS = {"commit", "push", "merge", "rebase", "tag", "cherry-pick", "am", "revert", "update-ref",
                         "filter-branch", "filter-repo", "replace"}
GIT_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix",
                     "--exec-path", "--attr-source"}
WRAPPERS = {"command", "exec", "nice", "nohup", "time", "env", "sudo", "doas", "builtin"}
# `qc.py review-record <id> <skill> <<'EOF' ... EOF` and nothing else: with a
# quoted delimiter the heredoc is passed to qc.py's stdin unexpanded, so its
# text (which names changed paths such as CLAUDE.md, and arrows such as "->")
# is data, not a command. The body ends at the first delimiter line, as in
# the shell; anything else in the command is checked as usual.
REVIEW_RECORD_RE = re.compile(
    r"\A\s*python3?\s+(?:\./)?\.claude/qc/qc\.py\s+review-record\s+[a-z0-9][a-z0-9-]*\s+"
    r"(?:engineering-code-review|arcium-security-review)\s*<<\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1[ \t]*\n"
    r"(?:(?!\2[ \t]*\n).*\n)*\2[ \t]*\n?\s*\Z")


def git_owner_only_tokens(cmd):
    """Whether any simple command in `cmd`, split as the shell would, is an owner-only git subcommand,
    whatever global options precede it. Commands that cannot be split are left to the regexes."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return False
    segments, cur = [], []
    for t in tokens:
        if t and all(c in ";&|()<>" for c in t):
            segments.append(cur)
            cur = []
        else:
            cur.append(t)
    segments.append(cur)
    for seg in segments:
        i = 0
        while i < len(seg) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i]) or seg[i] in WRAPPERS
                                or (i and seg[i - 1] in WRAPPERS and seg[i].startswith("-"))):
            i += 1
        if i >= len(seg) or os.path.basename(seg[i].strip("$`")) != "git":
            continue
        i += 1
        while i < len(seg) and seg[i].startswith("-"):
            opt = seg[i]
            if opt in GIT_OPTS_WITH_ARG:
                if opt == "-c" and i + 1 < len(seg) and seg[i + 1].lower().startswith("alias."):
                    return True  # an alias defined for this command could name any subcommand
                i += 2
            else:
                if opt.startswith("-c") and opt[2:].lower().startswith("alias."):
                    return True
                i += 1
        if i < len(seg):
            sub = seg[i]
            if sub in GIT_OWNER_SUBCOMMANDS and not (sub == "tag" and len(seg) > i + 1
                                                     and seg[i + 1] in ("-l", "--list")):
                return True
    return False


class Deadline(Exception):
    pass


def _deadline(_signum, _frame):
    raise Deadline("the QC guard ran out of time")


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": reason}}))


def starts(data):
    """Where this hook call may concern a clone: the payload's cwd, $CLAUDE_PROJECT_DIR, this file's."""
    cwd = data.get("cwd") if isinstance(data, dict) else None
    return [x for x in (cwd, os.environ.get("CLAUDE_PROJECT_DIR"), HERE) if isinstance(x, str) and x]


def roots(data):
    """(the distinct clones this call concerns, the start directories that could not be inspected although
    an activation record exists there). A directory outside any clone is neither."""
    out, unknown = [], []
    for start in starts(data):
        try:
            r = os.path.realpath(qc.repo_root(start))
        except Deadline:
            raise
        except Exception:  # noqa: BLE001 - not a clone, or git/qc.py failing there: the file system decides
            if activation_record_below(start):
                unknown.append(start)
            continue
        if r not in out:
            out.append(r)
    return out, unknown


def fail_closed(event, data, why):
    """While a loop is active and the guard cannot decide: never let the step through silently."""
    msg = "QC guard could not check this step (%s). The Owner releases the loop by deleting " \
          "<git-dir>/arcium-qc/active.json." % why
    if event == "pre-tool":
        deny(msg)
        return 0
    if event == "stop":
        if data.get("stop_hook_active"):
            print(json.dumps({"systemMessage": "QC WARNING: " + msg}))
        else:
            print(json.dumps({"decision": "block", "reason": msg + " Report the computed state with "
                              "qc.py verdict, never VERIFIED from memory."}))
        return 0
    if event == "task-completed":
        sys.stderr.write(msg + "\n")
        return 2
    return 0


def activation_record_below(start):
    """Whether the clone containing `start` has an activation record, found from the file system alone (no
    git, no qc.py; an expired record counts too): the fallback when the guard cannot inspect the clone.
    Never raises: a .git file or directory that cannot be read or decoded shows no record (the other start
    directories, such as $CLAUDE_PROJECT_DIR, are still looked at), so it never traps a session."""
    try:
        d = os.path.abspath(start)
        while True:
            dot = os.path.join(d, ".git")
            gitdir = None
            if os.path.isdir(dot):
                gitdir = dot
            elif os.path.isfile(dot):
                with open(dot, "rb") as f:
                    line = f.read(4096).strip()
                if not line.startswith(b"gitdir:"):
                    return False
                gitdir = os.path.join(os.fsencode(d), line[len(b"gitdir:"):].strip())
            if gitdir is not None:
                return os.path.lexists(os.path.join(os.fsencode(gitdir) if isinstance(gitdir, str) else gitdir,
                                                    b"arcium-qc", b"active.json"))
            parent = os.path.dirname(d)
            if parent == d:
                return False
            d = parent
    except Deadline:
        raise
    except Exception:  # noqa: BLE001 - unreadable or undecodable: no record seen here
        return False


def activation_file_exists(data):
    """Whether any clone this call may concern has an activation record (see activation_record_below)."""
    try:
        return any(activation_record_below(x) for x in starts(data))
    except Exception:  # noqa: BLE001 - only reachable through a bug; the other paths still decide
        return False


def main(event, data, input_error=None, stop_hint=False):
    """`input_error` says why the hook's input could not be read; the payload is then {} and only
    $CLAUDE_PROJECT_DIR and this file's clone are looked at. Any loop active there fails closed."""
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _deadline)
        signal.alarm(DEADLINE.get(event, 10))
    try:
        return _main(event, data, input_error, stop_hint)
    except Deadline as e:
        # Ran out of time before finding out whether a loop is active.
        if activation_file_exists(data):
            return fail_closed(event, {"stop_hook_active": stop_hint or data.get("stop_hook_active")}, str(e))
        return 0
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)


def _main(event, data, input_error, stop_hint):
    found, unknown = roots(data)
    if unknown:
        return fail_closed(event, {"stop_hook_active": stop_hint or data.get("stop_hook_active")},
                           "the clone of %s has an activation record but could not be inspected (git or qc.py "
                           "failed there)" % unknown[0])
    active = []
    for root in found:
        try:
            sid, invalid = qc.activation(root)
        except Deadline:
            raise
        except Exception:  # noqa: BLE001 - an activation that cannot be read counts as active
            sid, invalid = None, True
        if sid is not None or invalid:
            active.append((root, sid))
    if not active:
        return 0  # no active QC loop in any clone this call concerns: the guards do nothing
    if input_error:
        return fail_closed(event, {"stop_hook_active": stop_hint}, input_error)
    for root, sid in active:
        try:
            if sid is None:
                raise qc.QcError("BLOCKED", "the activation record is unreadable or fails its integrity check")
            code, text = io_capture(check, event, data, root, sid)
            if code or text:
                sys.stdout.write(text)
                return code
        except Exception as e:  # noqa: BLE001 - an active loop never fails open
            return fail_closed(event, data, "%s: %s" % (type(e).__name__, e))
    return 0


def io_capture(fn, *args):
    """(exit code, stdout text) of fn: output is written only once the check finished without error."""
    buf, old = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        code = fn(*args)
    finally:
        sys.stdout = old
    return code, buf.getvalue()


def check(event, data, root, sid):
    if event == "stop":
        msg = data.get("last_assistant_message") or ""
        claims = CLAIM_RE.findall(msg)
        if data.get("stop_hook_active"):
            # Never block twice. A claim that is still false is shown to the
            # person instead, so it cannot pass unnoticed.
            if "VERIFIED" in claims:
                state, why = qc.verdict(root, sid)
                if state != "VERIFIED":
                    print(json.dumps({"systemMessage": "QC WARNING: the final message claims QC_STATE: VERIFIED, "
                                      "but qc.py verdict for %s is %s (%s)." % (sid, state, why)}))
            return 0
        state, why = qc.verdict(root, sid)
        if "VERIFIED" in claims and state != "VERIFIED":
            print(json.dumps({"decision": "block", "reason":
                              "QC loop %s: you reported QC_STATE: VERIFIED, but qc.py verdict is %s (%s). "
                              "Report the computed state; never write VERIFIED yourself." % (sid, state, why)}))
        elif state == "ESCALATE_TO_OWNER" and (not claims or claims[-1] not in ("ESCALATE_TO_OWNER", "BLOCKED")):
            print(json.dumps({"decision": "block", "reason":
                              "QC loop %s is ESCALATE_TO_OWNER (%s). Stop repairing and report that state "
                              "to the Owner." % (sid, why)}))
        return 0

    if event == "task-completed":
        subject = "%s %s" % (data.get("task_subject", ""), data.get("task_description", ""))
        if "[qc]" not in subject:
            return 0
        state, why = qc.verdict(root, sid)
        if state != "VERIFIED":
            sys.stderr.write("QC loop %s: this task cannot be completed while the verdict is %s (%s).\n"
                             % (sid, state, why))
            return 2
        return 0

    if event == "pre-tool":
        tool = data.get("tool_name", "")
        ti = data.get("tool_input") or {}
        if tool == "Bash":
            cmd = str(ti.get("command", ""))
            if REVIEW_RECORD_RE.match(cmd):
                return 0
            cmd = re.sub(r"\\\r?\n", "", cmd)  # a line continuation joins its lines, as in the shell
            if GIT_OWNER_ONLY.search(cmd) or OTHER_OWNER_ONLY.search(cmd) or git_owner_only_tokens(cmd):
                deny("QC loop %s is active: this is an owner-only operation (commit/push/merge/PR/dispatch/"
                     "deploy). Report to the Owner instead." % sid)
            elif BASH_WRITES_PROTECTED.search(cmd):
                deny("QC loop %s is active: the QC tool, hooks, agent settings and CLAUDE.md are not "
                     "edited during a loop." % sid)
        elif MCP_WRITE.match(tool):
            deny("QC loop %s is active: GitHub write operations are owner-only." % sid)
        elif tool in ("Edit", "Write", "NotebookEdit", "MultiEdit"):
            path = str(ti.get("file_path") or ti.get("notebook_path") or "")
            if PROTECTED.search(path):
                deny("QC loop %s is active: %s is part of the QC/agent control plane." % (sid, path))
        return 0
    return 0


# Hook input above this size is not parsed: with a loop active it fails closed.
MAX_INPUT = 16 << 20
# An unescaped "stop_hook_active": true, as a top-level key would appear (inside a JSON string the quotes
# would be escaped): lets a payload that cannot be parsed still block a stop only once.
STOP_ACTIVE_RE = re.compile(rb'(?<!\\)"stop_hook_active"\s*:\s*true')


def read_input(stream):
    """(payload, why it is unusable or None, whether it says stop_hook_active). Reads at most
    MAX_INPUT + 1 bytes; a payload that is too large, unreadable, not JSON or not an object is unusable."""
    try:
        raw = stream.read(MAX_INPUT + 1)
    except Exception as e:  # noqa: BLE001 - unreadable input is reported, never accepted
        return {}, "the hook input could not be read (%s)" % type(e).__name__, False
    hint = bool(STOP_ACTIVE_RE.search(raw))
    if len(raw) > MAX_INPUT:
        return {}, "the hook input is larger than %d bytes" % MAX_INPUT, hint
    if not raw.strip():
        return {}, "the hook input is empty", False
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - not JSON, not UTF-8, too deeply nested (RecursionError), no memory
        return {}, "the hook input is not usable JSON", hint
    if not isinstance(data, dict):
        return {}, "the hook input is not a JSON object", hint
    return data, None, hint


if __name__ == "__main__":
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    payload, why, hint = {}, "the hook input could not be read", False
    try:
        try:
            if hasattr(signal, "SIGALRM"):
                signal.signal(signal.SIGALRM, _deadline)
                signal.alarm(READ_DEADLINE)  # input that never ends is unusable input
            payload, why, hint = read_input(sys.stdin.buffer)
        finally:
            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)
    except BaseException:  # noqa: BLE001 - also a deadline firing just as the read ends: the input is unusable
        payload, why, hint = {}, "the hook input could not be read in time", hint
    try:
        sys.exit(main(event, payload, input_error=why, stop_hint=hint))
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001 - main itself failed: decide from the file system alone
        try:
            found = activation_file_exists(payload)
        except BaseException:  # noqa: BLE001 - a deadline still pending: assume the worst only if asked to
            found = False
        if found:
            sys.exit(fail_closed(event, {"stop_hook_active": hint}, "%s: %s" % (type(e).__name__, e)))
        sys.exit(0)
