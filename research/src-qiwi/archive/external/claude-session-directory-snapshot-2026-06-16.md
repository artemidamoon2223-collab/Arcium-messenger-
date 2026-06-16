# Archive: Claude Session Directory Snapshot (2026-06-16)

- **Snapshot date:** 2026-06-16
- **Snapshot time (approximate):** 2026-06-16T17:32 UTC
- **Source type:** Local Filesystem Snapshot
- **Status:** Raw Historical Material
- **Processing status:** Not Yet Reviewed

---

## Directory inspected

```
/root/.claude/projects/-home-user-Arcium-messenger-/
```

## Commands used

```
ls -la /root/.claude/projects/-home-user-Arcium-messenger-/
find /root/.claude/projects/-home-user-Arcium-messenger-/ -maxdepth 2 | sort
```

---

## Directory listing

```
total 816
drwx------ 3 root root   4096 Jun 15 00:18 . (parent directory)
drwx------ 3 root root   4096 Jun 15 00:18 ..
drwxr-xr-x 4 root root   4096 Jun 16 04:16 dd02cdb5-8330-56b1-bb95-dd58d85d1a86/
-rw------- 1 root root 820198 Jun 16 17:32 dd02cdb5-8330-56b1-bb95-dd58d85d1a86.jsonl
```

## Full recursive listing (depth 2)

```
/root/.claude/projects/-home-user-Arcium-messenger-/
/root/.claude/projects/-home-user-Arcium-messenger-/dd02cdb5-8330-56b1-bb95-dd58d85d1a86
/root/.claude/projects/-home-user-Arcium-messenger-/dd02cdb5-8330-56b1-bb95-dd58d85d1a86/subagents
/root/.claude/projects/-home-user-Arcium-messenger-/dd02cdb5-8330-56b1-bb95-dd58d85d1a86/tool-results
/root/.claude/projects/-home-user-Arcium-messenger-/dd02cdb5-8330-56b1-bb95-dd58d85d1a86.jsonl
```

---

## Findings

### Session JSONL files present

| Filename | Size | Modified |
|----------|------|----------|
| `dd02cdb5-8330-56b1-bb95-dd58d85d1a86.jsonl` | 820,198 bytes | 2026-06-16 17:32 UTC |

### Session JSONL files other than dd02cdb5-8330-56b1-bb95-dd58d85d1a86.jsonl

None found.

### Prior session JSONL predating first SRC/QIWI commit (e277868, 2026-06-15T03:36:04 UTC)

None found. The only JSONL present is
`dd02cdb5-8330-56b1-bb95-dd58d85d1a86.jsonl`, last modified
2026-06-16T17:32 UTC (an active session file, not a prior session).

The parent directory itself (`-home-user-Arcium-messenger-/`) shows a
creation timestamp of Jun 15 00:18 — consistent with the session
dd02cdb5 start time recorded in Observation-004.

---

## Scope limitation

This snapshot reflects the state of the local container filesystem at
the time of the snapshot. It does not cover:

- Session data held in Anthropic cloud infrastructure
- Sessions that may have existed and been deleted before this snapshot
- Sessions associated with this repository path in other containers or
  environments
- Any session storage outside the inspected directory

The absence of other JSONL files in this directory is a local finding
only.

---

End of snapshot. This file should not be treated as a source of
observations, predictions, or cases until reviewed separately through
the process described in `OBJECT_OF_STUDY.md`.
