# SRC/QIWI Repository Map

A 10-minute orientation document for a new agent. This file is itself
archival/navigational — it makes no observations, predictions, or status
claims of its own. It only indexes and summarizes what already exists in
`predictions.md`, `cases.md`, `OBSERVATIONS.md`, and `HANDOVER.md`.

---

## 1. Directory structure

```
research/src-qiwi/
├── REPOSITORY_MAP.md          # this file
├── README.md                  # what SRC/QIWI is / is not
├── OBJECT_OF_STUDY.md          # what this area tracks, status vocabulary
├── HANDOVER.md                 # entry point for a fresh agent
├── OBSERVATIONS.md             # log of sourced observations
├── predictions.md              # open claims and move conditions
├── cases.md                    # recorded mismatches (currently empty)
└── archive/
    ├── audits/
    │   └── behavioral-protocol-test-2026-06-16.md
    ├── conversations/
    │   ├── origins-batch-001.md
    │   ├── repository-evolution-batch-001.md
    │   └── session-origin-2026-06-15.md
    ├── external/
    │   ├── claude-session-directory-snapshot-2026-06-16.md
    │   ├── npm-pi-shipshape-2026-06-15.md
    │   └── pi-shipshape-full-version-vocabulary-audit-2026-06-16.md
    └── investigations/
        └── excerpt2-evidence-ceiling-2026-06-16.md
```

---

## 2. Canonical files

These five files define the research framework and its current state:

- `README.md` — scope statement (what SRC/QIWI is / is not).
- `OBJECT_OF_STUDY.md` — defines the three tracked record types
  (observations, predictions, cases) and their status vocabularies.
- `HANDOVER.md` — current agent state, bottleneck, read order, ceilings.
- `OBSERVATIONS.md` — the sourced-event log (Observation-001 through
  Observation-007).
- `predictions.md` — the open-claims log (Prediction-A, Prediction-C,
  Prediction-D).

`cases.md` is also canonical by definition (per `OBJECT_OF_STUDY.md`) but
currently contains no entries (`[SOURCE NOT FOUND] — no cases recorded
yet.`).

---

## 3. Source of truth

| Question | Source of truth |
|---|---|
| Current prediction statuses | `predictions.md` |
| What evidence supports/weakens a prediction | `predictions.md` (cites Observation-NNN) |
| Raw sourced facts | `OBSERVATIONS.md` |
| Whether a mismatch/case is open | `cases.md` |
| What phase the research is in, what's blocking it | `HANDOVER.md` |
| What counts as an observation/prediction/case, status rules | `OBJECT_OF_STUDY.md` |
| Scope boundary vs. the messenger app | `README.md` and root `CLAUDE.md` ("Граница проектов") |

If any archive file appears to conflict with `predictions.md` or
`OBSERVATIONS.md`, the top-level files win — archive files are raw/source
material, not conclusions.

---

## 4. Archival-only files

Everything under `archive/` is source material or process record, not a
place where conclusions live:

- `archive/conversations/` — transcripts/records of how SRC/QIWI content
  was received (`session-origin-2026-06-15.md` contains "Excerpt 2",
  marked `[PROVENANCE UNVERIFIED]`; `origins-batch-001.md` records
  authorship as `[SOURCE NOT FOUND]`; `repository-evolution-batch-001.md`
  is a git-history inventory).
- `archive/external/` — external snapshots (npm package metadata, a
  pi-shipshape version vocabulary audit, a Claude session directory
  snapshot). These are inputs cited by observations, not conclusions
  themselves.
- `archive/investigations/excerpt2-evidence-ceiling-2026-06-16.md` — a
  paused-investigation record. It documents which local source categories
  have already been exhausted (git history, archive files, JSONL
  metadata, MCP metadata, filesystem metadata, working-tree search) so a
  future agent does not repeat them.
- `archive/audits/behavioral-protocol-test-2026-06-16.md` — a record of
  agent behavior during one session turn (a suspected prompt-injection
  message and how it was handled). Explicitly not an observation,
  prediction, or case.

---

## 5. Active predictions (as recorded in `predictions.md`)

| ID | Claim (short) | Status |
|---|---|---|
| Prediction-A | SRC/QIWI originated from a prior agent session predating dd02cdb5 | `weakened` |
| Prediction-C | SRC/QIWI was synthesized in-session during dd02cdb5 (2026-06-15T00:18–03:36 UTC) | `supported weak` |
| Prediction-D | pi-shipshape@0.1.15 was the direct template/vocabulary source | `falsified` |

Full claim text, supporting/weakening observations, and move conditions
for each are in `predictions.md` — this table is a pointer, not a
restatement of evidence.

---

## 6. Current ceilings (as recorded in `HANDOVER.md`)

- **Prediction-D:** terminal (`falsified`). No further action.
- **Prediction-A:** `weakened`; cannot move further using locally
  accessible sources. Would require non-local/cloud session evidence
  (Anthropic infrastructure) for session `dd02cdb5`.
- **Prediction-C:** frozen at `supported weak`; resume only if the
  gap-era transcript (2026-06-15T00:18–03:36 UTC) or an equivalent source
  becomes available.
- All six locally-exhausted source categories (git history, archive
  files, JSONL metadata, MCP metadata, filesystem metadata, working-tree
  search) are detailed in
  `archive/investigations/excerpt2-evidence-ceiling-2026-06-16.md` and
  should not be re-investigated.

---

## 7. Current investigation status

- **Phase:** DATA ACQUISITION (per `HANDOVER.md`).
- **Main bottleneck:** lack of observations capable of changing beliefs.
- **Architecture status:** frozen — not to be expanded without evidence.
- **Stopping condition met:** Excerpt 2 provenance and Prediction-A/C are
  all blocked on the same missing source category — Anthropic cloud
  session records for `dd02cdb5-8330-56b1-bb95-dd58d85d1a86` covering
  approximately 2026-06-15T00:18–03:36 UTC. This is documented as **not
  available locally** in
  `archive/investigations/excerpt2-evidence-ceiling-2026-06-16.md`.
- **New entries policy:** per `HANDOVER.md`, new observations are recorded
  only after human review and explicit approval. Updating a prediction's
  status requires a new observation that satisfies that prediction's
  recorded move condition — analytical argument alone does not qualify.

---

## 8. Read order for a new agent

1. `HANDOVER.md` — current state, bottleneck, ceilings.
2. `OBJECT_OF_STUDY.md` — what is tracked, status rules.
3. `predictions.md` — open claims.
4. `cases.md` — recorded mismatches (currently empty).
5. `OBSERVATIONS.md` — sourced events backing the predictions.
6. `archive/investigations/excerpt2-evidence-ceiling-2026-06-16.md` — if
   touching Prediction-A, Prediction-C, or Excerpt 2 provenance, read this
   before doing anything else, to avoid re-investigating exhausted
   categories.
7. `archive/` subdirectories — only as needed to verify a specific cited
   source.

---

End of map.
