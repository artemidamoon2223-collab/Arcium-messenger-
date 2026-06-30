# SRC/QIWI — Research Memory Area

SRC/QIWI is an isolated research memory area for an experimental
research agent, kept separate from the Arcium Messenger application
code.

It exists to preserve agent reasoning state — observations,
predictions, open cases, and handoff notes — as durable repository
artifacts instead of relying on chat history that does not survive
`/clear`.

## What this is not

- Not messenger application code.
- Not a new agent, service, or runtime component.
- Not a package or dependency.

## Long-term purpose

[SOURCE NOT FOUND] — the long-term purpose of SRC/QIWI beyond the
above is a working interpretation, not a settled fact.

## Files

- `HANDOVER.md` — entry point for a fresh agent; agent state and read order.
- `OBJECT_OF_STUDY.md` — what this area tracks and status vocabulary.
- `OBSERVATIONS.md` — log of sourced observations.
- `predictions.md` — open claims and their move conditions.
- `cases.md` — recorded mismatches / cases.
- `archive/` — source material (session transcripts, external snapshots, git history).
