# Predictions

Open claims and the conditions under which their status may change.
A status change requires a sourced observation, not argument alone.

## Status values

- `pending`
- `supported`
- `supported weak`
- `weakened`
- `falsified`
- `unknown`

## Log

### Prediction-A

**Claim:** SRC/QIWI originated from a prior agent session whose
artifacts predate session dd02cdb5 and are not present in the local
environment.

**Status:** `weakened`

**Supporting observations:** None from Observation-001–007.

**Weakening observations:**
- Observation-004: Session dd02cdb5 is the active session throughout
  the gap interval; no prior session UUID or prior JSONL is recorded
  locally. Note: MCP logs are non-persistent — absence in local cache
  does not constitute evidence of non-existence.
- Observation-007: A durable local snapshot confirmed that only one
  session JSONL exists for this repository path
  (`dd02cdb5-8330-56b1-bb95-dd58d85d1a86.jsonl`); no prior session
  JSONL predating `e277868` was found locally. Caveat: does not rule
  out non-local, cloud, external, deleted, or inaccessible prior
  sessions.

**Move conditions:**
- → `supported`: A prior session transcript or repository artifact
  predating 2026-06-15T03:36:04 UTC is found containing SRC/QIWI
  vocabulary, backed by a durable source.
- → `weakened`: ✓ Met by Observation-007 — local absence confirmed
  via committed durable artifact.
- → `falsified`: Confirmed absence of any prior session through
  durable evidence extending beyond local storage (e.g., Anthropic
  infrastructure records).

---

### Prediction-C

**Claim:** SRC/QIWI vocabulary and structure were synthesized within
the gap session (dd02cdb5, 2026-06-15T00:18–03:36 UTC) from sources
available to the agent during that interval.

**Status:** `supported weak`

**Evidence basis note:** Support derives from elimination of alternative
explanations (Obs-003, Obs-006) and timing consistency (Obs-002,
Obs-004), not from direct observation of the synthesis mechanism.
The specific in-session source(s), the origin path of Excerpt 2, and
whether a prior conversational process existed remain unknown. No
sourced observation directly identifies the mechanism responsible for
the observed vocabulary and structure, which is why this prediction
does not meet the conditions for `supported`. No durable observation
currently contradicts it, which is why it has not moved to `weakened`.
See `archive/investigations/excerpt2-evidence-ceiling-2026-06-16.md`
for the full record of exhausted local source categories.

**Supporting observations:**
- Observation-003: Zero SRC/QIWI vocabulary found in
  pi-shipshape@0.1.15, eliminating it as a vocabulary source and
  leaving in-session synthesis as the remaining uneliminated
  mechanism.
- Observation-006: Zero SRC/QIWI vocabulary confirmed across all 9
  published pi-shipshape versions (0.1.7–0.1.15), extending the
  elimination to the complete version space.
- Observation-004: Session dd02cdb5 was active throughout the full
  gap interval (~3h18m), consistent with the time required for
  in-session synthesis.
- Observation-002: The ~3h18m gap between npm query and first commit
  is consistent with a single continuous session.

**Weakening observations:** None from Observation-001–007.

**Move conditions:**
- → `supported`: The specific in-session source(s) used to produce
  SRC/QIWI vocabulary are identified via a durable sourced
  observation.
- → `weakened`: An artifact predating 2026-06-15 is found containing
  SRC/QIWI vocabulary, backed by a durable source.
- → `falsified`: A prior session transcript containing SRC/QIWI
  framework is confirmed via a durable source.

---

### Prediction-D

**Claim:** pi-shipshape@0.1.15 served as the direct template or
primary vocabulary source for SRC/QIWI structure.

**Status:** `falsified`

**Supporting observations:**
- Observation-001: pi-shipshape@0.1.15 was the package referenced in
  the first session message, establishing it as the initial subject
  of the session.

**Weakening observations:**
- Observation-003: Zero SRC/QIWI vocabulary found in
  pi-shipshape@0.1.15. The package implements a BDD/Gherkin workflow
  (spec-driven, Captain/QM/Crew/Bosun roles) structurally distinct
  from SRC/QIWI's observation-tracking framework.

**Falsifying observations:**
- Observation-006: Zero SRC/QIWI vocabulary across the complete
  published version space (0.1.7–0.1.15); versions 0.1.0–0.1.6
  confirmed unpublished. Satisfies the recorded falsification move
  condition.

**Move conditions:**
- → `falsified`: Zero SRC/QIWI vocabulary confirmed across all
  pi-shipshape versions (0.1.0–0.1.15) via durable sourced
  observations. ✓ Met by Observation-006.
- → `supported`: SRC/QIWI vocabulary found in a pi-shipshape version
  via a durable sourced observation.
