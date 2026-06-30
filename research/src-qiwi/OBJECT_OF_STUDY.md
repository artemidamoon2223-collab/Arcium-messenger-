# Object of Study

This file describes what `research/src-qiwi/` tracks.

- **Observations** (`OBSERVATIONS.md`) — sourced events, each citing
  its source (record, run, or document).
- **Predictions** (`predictions.md`) — open claims and the conditions
  under which their status may change
  (`pending` / `supported` / `supported weak` / `weakened` /
  `falsified` / `unknown`).
- **Cases** (`cases.md`) — recorded mismatches between expectation and
  observation
  (`pending` / `unknown` / `unverified` / `confirmed` / `closed`).
- **Status transitions** — any change to a prediction's or case's
  status must be backed by a sourced observation, not argument alone.

## Provenance

Every observation, prediction, and case claim carries one of these
labels:

- `observed` — produced directly from a source via an observation
  (source → observation).
- `derived-empirical` — produced from execution or measurement of an
  observed artifact.
- `derived-analytical` — deduced from accepted definitions rather
  than from a source; cites the definitions it rests on; labeled
  `analytical`, and marked "conditionally analytical" if it holds
  only under the current framing.

These labels are never collapsed into one another. An analytical
claim is never relabeled as an observation.

## Unknown subtypes

The `unknown` status (see vocabularies above) has two subtypes:

- **Type A — analysis-limited:** investigation may continue; more
  reasoning over existing sources can still resolve it.
- **Type B — evidence-limited:** pause; resolution requires a new
  source category not yet available.

## Out of scope

- Messenger runtime code, build configuration, and dependencies.
- Any executable tooling.
