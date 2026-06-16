# Handover

A future agent should continue from the artifacts in this directory,
not from inherited chat context.

## Agent state

- **Current phase:** DATA ACQUISITION
- **Main bottleneck:** lack of observations capable of changing beliefs
- **Architecture status:** frozen — do not expand without evidence
- **Purpose status:** working interpretation, not a settled fact

New entries should be recorded as observations only after human review
and explicit approval.

## Read order

1. `OBJECT_OF_STUDY.md` — what this area tracks and status rules
2. `predictions.md` — open claims
3. `cases.md` — recorded mismatches
4. `OBSERVATIONS.md` — sourced events

This directory is an isolated research memory area inside the Arcium
Messenger repository. It does not describe or affect the messenger
application, and the messenger application does not depend on it.

## Current state

- `research/src-qiwi/` exists as an isolated research area.
- Messenger code was not modified.

This does not constitute a status transition for any prediction.

## Handoff risks

- The purpose of this research area is a working interpretation, not a
  settled fact.
- Prior chat history is not captured here and should not be assumed by
  a future agent.
