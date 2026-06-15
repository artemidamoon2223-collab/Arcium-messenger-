# SRC/QIWI — Research Memory Area

SRC/QIWI is an isolated research memory area for an experimental
research agent, kept separate from the Arcium Messenger application
code.

It exists to preserve agent reasoning state — observations,
predictions, open cases, and handoff notes — as durable repository
artifacts instead of relying on chat history that does not survive
`/clear`.

This directory was introduced by this commit. It contains no messenger
runtime code and is not referenced by any Rust, Android, Gradle, or
Cargo build configuration.

## Files

- `AGENT_STATE.md` — current phase and status of the research agent.
- `OBSERVATIONS.md` — log of sourced observations.
- `predictions.md` — open claims and their move conditions.
- `cases.md` — recorded mismatches / cases.
- `HANDOVER.md` — how a future agent should pick up this work.
- `REMAINING_HANDOFF_RISKS.md` — known gaps and open risks.
