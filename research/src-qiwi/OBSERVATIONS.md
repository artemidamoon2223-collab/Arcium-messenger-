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
