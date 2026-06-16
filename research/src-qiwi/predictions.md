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

**Status:** `unknown`

**Supporting observations:** None from Observation-001–005.

**Weakening observations:**
- Observation-004: Session dd02cdb5 is the active session throughout
  the gap interval; no prior session UUID or prior JSONL is recorded
  locally. Note: MCP logs are non-persistent — absence in local cache
  does not constitute evidence of non-existence.

**Move conditions:**
- → `supported`: A prior session transcript or repository artifact
  predating 2026-06-15T03:36:04 UTC is found containing SRC/QIWI
  vocabulary, backed by a durable source.
- → `weakened`: Observation-004's absence evidence is confirmed via a
  durable artifact (not non-persistent MCP logs alone).
- → `falsified`: Confirmed absence of any prior session through
  durable evidence establishing that dd02cdb5 was the first session
  in this repository context.

---

### Prediction-C

**Claim:** SRC/QIWI vocabulary and structure were synthesized within
the gap session (dd02cdb5, 2026-06-15T00:18–03:36 UTC) from sources
available to the agent during that interval.

**Status:** `supported weak`

**Supporting observations:**
- Observation-003: Zero SRC/QIWI vocabulary found in
  pi-shipshape@0.1.15, eliminating it as a vocabulary source and
  leaving in-session synthesis as the remaining uneliminated
  mechanism.
- Observation-004: Session dd02cdb5 was active throughout the full
  gap interval (~3h18m), consistent with the time required for
  in-session synthesis.
- Observation-002: The ~3h18m gap between npm query and first commit
  is consistent with a single continuous session.

**Weakening observations:** None from Observation-001–005.

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

**Status:** `weakened`

**Supporting observations:**
- Observation-001: pi-shipshape@0.1.15 was the package referenced in
  the first session message, establishing it as the initial subject
  of the session.

**Weakening observations:**
- Observation-003: Zero SRC/QIWI vocabulary found in
  pi-shipshape@0.1.15. The package implements a BDD/Gherkin workflow
  (spec-driven, Captain/QM/Crew/Bosun roles) structurally distinct
  from SRC/QIWI's observation-tracking framework.

**Move conditions:**
- → `falsified`: Zero SRC/QIWI vocabulary confirmed across all
  pi-shipshape versions (0.1.0–0.1.15) via durable sourced
  observations.
- → `supported`: SRC/QIWI vocabulary found in a pi-shipshape version
  via a durable sourced observation.
