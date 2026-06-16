# Observations

A log of sourced observations. Each entry must cite its source
(record, run, or document). Do not back-fill entries from chat memory.

## Log

### Observation-001

**Observation:** The package referenced in the first archived session
message corresponds to the package `pi-shipshape@0.1.15` documented in
the archived npm registry snapshot.

**Source:**
- `archive/conversations/session-origin-2026-06-15.md`
- `archive/external/npm-pi-shipshape-2026-06-15.md`

**Status:** recorded

### Observation-002

**Observation:** The npm snapshot query time recorded in
`archive/external/npm-pi-shipshape-2026-06-15.md` and the first commit
creating `research/src-qiwi/` (`e277868`) are separated by
approximately 3h18m based on the timestamps recorded in those sources.

**Source:**
- `archive/external/npm-pi-shipshape-2026-06-15.md`
- `archive/conversations/origins-batch-001.md`
- `archive/conversations/repository-evolution-batch-001.md`

**Status:** recorded

### Observation-003

**Observation:** A grep of the extracted pi-shipshape package (version
0.1.15, at `/tmp/pi-shipshape-inspect/package/`) finds zero occurrences
of any of the following terms that appear in the SRC/QIWI framework:
`INDETERMINATE`, `predictions`, `observation`, `[SOURCE NOT FOUND]`,
`pending`, `supported`, `weakened`, `falsified`, `cases.md`,
`OBSERVATIONS`. The package implements a software development workflow
(spec-driven, Gherkin/BDD, Captain/QM/Crew/Bosun roles) that is
structurally distinct from the SRC/QIWI observation-tracking framework.
The Shipshape core vocabulary ("durable", "handoff", "fresh agent",
"context-isolated") is present in pi-shipshape but absent from the
SRC/QIWI status/log/case vocabulary.

**Source:**
- Live grep of `/tmp/pi-shipshape-inspect/package/` (package extracted
  from `pi-shipshape-0.1.15.tgz` present in the same directory); this
  is a filesystem artifact from the prior session (2026-06-15) and is
  not a committed repository artifact — it may not persist.
- `archive/external/npm-pi-shipshape-2026-06-15.md` independently
  corroborates package identity: `pi-shipshape@0.1.15`,
  shasum `71a11c7ed7de5224d0f0322a7874044f7200da65`.

**Status:** recorded

### Observation-004

**Observation:** During the interval between the npm pi-shipshape query
(~00:18 UTC, 2026-06-15) and the first `research/src-qiwi/` commit
(03:36:04 UTC, 2026-06-15), the Claude session `dd02cdb5` was active.
Multiple GitHub MCP connection logs exist for this session, showing at
least 8 reconnection events between approximately 00:18 UTC and 03:35
UTC — each representing an agent turn with GitHub MCP available. No
tool calls other than the one documented in Observation-005 are recorded
in the gap-era logs.

**Source:**
- Local MCP logs at `/root/.cache/claude-cli-nodejs/-home-user-Arcium-messenger-/mcp-logs-github/`
  (8 gap-era files: `2026-06-15T00-18-30-709Z.jsonl`,
  `2026-06-15T01-41-19-799Z.jsonl`, `2026-06-15T01-50-14-691Z.jsonl`,
  `2026-06-15T02-49-45-471Z.jsonl`, `2026-06-15T02-59-08-889Z.jsonl`,
  `2026-06-15T03-28-40-450Z.jsonl`, `2026-06-15T03-35-10-582Z.jsonl`,
  and `2026-06-15T02-27-06-088Z.jsonl`). These are local filesystem
  artifacts, not committed repository files — they may not persist
  across container restarts.
- `archive/external/npm-pi-shipshape-2026-06-15.md` (gap start anchor:
  npm query at ~00:18 UTC)
- git commit `e277868` (gap end anchor: first `research/src-qiwi/`
  commit at 2026-06-15T03:36:04 UTC)

**Status:** recorded

### Observation-005

**Observation:** During the gap interval, one GitHub MCP tool call
occurred: `search_repositories` was called at approximately
2026-06-15T02:27:46 UTC and completed successfully in 501ms. The local
MCP log records the tool name, call time, and completion status only.
The query parameters and results are not preserved in the local log.

**Source:**
- Local MCP log `/root/.cache/claude-cli-nodejs/-home-user-Arcium-messenger-/mcp-logs-github/2026-06-15T02-27-06-088Z.jsonl`
  (local filesystem artifact, not a committed repository file — may not
  persist across container restarts)
- git commit `e277868` (contextual anchor: first `research/src-qiwi/`
  commit at 2026-06-15T03:36:04 UTC, approximately 1h08m after this
  tool call)

**Status:** recorded

### Observation-006

**Observation:** A complete audit of all published pi-shipshape versions
found that versions 0.1.0–0.1.6 were not published, and versions
0.1.7–0.1.15 contained zero matches for the SRC/QIWI-specific vocabulary
terms `INDETERMINATE`, `[SOURCE NOT FOUND]`, `OBSERVATIONS`,
`predictions`, `cases.md`, `weakened`, and `falsified`.

**Source:**
- `archive/external/pi-shipshape-full-version-vocabulary-audit-2026-06-16.md`
- `archive/external/npm-pi-shipshape-2026-06-15.md`

**Status:** recorded
