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

## Lean workflow rules

- **New observation threshold:** Create an observation only when a
  previously unaccessed source produces a measurable fact. Re-reading
  an existing source does not qualify.

- **Prediction update threshold:** Update a prediction only when a new
  observation satisfies that prediction's recorded move condition.
  Analytical argument alone is not sufficient.

- **Investigation stopping condition:** Stop when no unaccessed source
  category remains, or when the required source category is identified
  and confirmed inaccessible locally. Document the ceiling explicitly;
  do not re-investigate exhausted categories.

### Current ceilings

- **Prediction-D:** terminal — `falsified`. No further action.
- **Prediction-A:** `weakened` — cannot move further locally without
  non-local or cloud session evidence (Anthropic infrastructure).
- **Prediction-C:** frozen at `supported weak` — resume only if
  gap-era transcript content (2026-06-15T00:18–03:36 UTC) or
  equivalent source becomes available.

## Handoff risks

- The purpose of this research area is a working interpretation, not a
  settled fact.
- Prior chat history is not captured here and should not be assumed by
  a future agent.
