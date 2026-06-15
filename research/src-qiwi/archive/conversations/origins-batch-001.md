# Archive: Origins Batch 001 — Source Inventory (2026-06-15)

- **Date:** 2026-06-15
- **Source type:** Historical Source Inventory
- **Status:** Historical Source Inventory
- **Processing status:** Not Yet Reviewed

This file is a source inventory only. It catalogs currently known
origins-related materials, their source type, and their raw/derived
classification, and lists the git-history timeline of
`research/src-qiwi/`. It does not narrate events, explain motives,
infer intent, or draw conclusions beyond inventory. No observations,
predictions, or cases have been derived from it.

---

## 1. Source inventory

### 1.1 `archive/conversations/session-origin-2026-06-15.md`

- **Source type:** Session Transcript (partial, curated excerpt selection).
- **Raw vs derived:** Mixed. The file presents two items as verbatim
  excerpts (raw quotation), assembled into a curated selection
  (derived container). The file states it is "a selection of verbatim
  excerpts from the session transcript... not the full transcript."
- **Contents, as described in the source file:**
  - Excerpt 1 — first message of the session.
  - Excerpt 2 — a document titled "Claude Code Operating Instructions
    for SRC/QIWI," marked `[PROVENANCE UNVERIFIED]` and
    `[PARTIAL SOURCE]` within the source file itself.
- **Status recorded in source file:** Raw Historical Material,
  Processing status: Not Yet Reviewed.

### 1.2 `archive/external/npm-pi-shipshape-2026-06-15.md`

- **Source type:** External Snapshot (npm registry, single query output).
- **Raw vs derived:** Raw. The file states it reflects "the output of
  a single `npm view pi-shipshape` query," and that "no summarization,
  interpretation, risk evaluation, or conclusions have been added."
- **Contents, as described in the source file:** registry fields for
  `pi-shipshape@0.1.15` (version, maintainer, publish timing as
  reported at query time, license, dependencies, total published
  versions, dist-tags, description, homepage, keywords, dist.tarball,
  dist.shasum, dist.integrity, dist.unpackedSize).
- **Status recorded in source file:** Raw Historical Material,
  Processing status: Not Yet Reviewed.

### 1.3 Git history of `research/src-qiwi/`

- **Source type:** Repository History (commit metadata, machine-generated).
- **Raw vs derived:** Mixed. Commit hashes, timestamps, and file diffs
  are raw repository records (independently reproducible via `git log`
  / `git show`). Commit messages are authored text layered on top of
  those records.

---

## 2. Git-history timeline of `research/src-qiwi/`

| Commit | Timestamp (UTC) | Message (first line) | Files touched |
|---|---|---|---|
| `e277868846efd75502781d73bb33f2e2f76d686b` | 2026-06-15T03:36:04+00:00 | Add isolated research/src-qiwi/ memory area | `AGENT_STATE.md`, `HANDOVER.md`, `OBSERVATIONS.md`, `README.md`, `REMAINING_HANDOFF_RISKS.md`, `cases.md`, `predictions.md` (7 files, 95 insertions) |
| `5b1fabe6f212993392970b8a46b5a0d5a4a2a185` | 2026-06-15T03:53:27+00:00 | Record neutral fact in SRC/QIWI memory area | `AGENT_STATE.md`, `HANDOVER.md` (2 files, 13 insertions) |
| `7a39cd2838c9f7d44d71655cded7a7a32f48f999` | 2026-06-15T16:26:27+00:00 | Add PROJECT_SCOPE.md, OBJECT_OF_STUDY.md, archive/reviews/ to SRC/QIWI | `OBJECT_OF_STUDY.md`, `PROJECT_SCOPE.md`, `archive/reviews/README.md` (3 files, 54 insertions) |
| `5d3ab23298987a9acce737a9e7e159bd158f0419` | 2026-06-15T17:12:14+00:00 | Archive earliest SRC/QIWI session-origin material (raw, unreviewed) | `archive/conversations/session-origin-2026-06-15.md` |
| `cf25703937054feac349843d955ff3ef94428695` | 2026-06-15T17:22:59+00:00 | Archive npm registry snapshot for pi-shipshape (raw, unreviewed) | `archive/external/npm-pi-shipshape-2026-06-15.md` |
| `7396dc5ff0a1253de7fc8b995345a0658cdcb74e` | 2026-06-15T17:27:24+00:00 | Record Observation-001 in SRC/QIWI | `OBSERVATIONS.md` |

All six commits carry the author `Claude <noreply@anthropic.com>` and
reference the same session URL
(`https://claude.ai/code/session_01GBgGzxjY47u8TNVqvDxMWy`) in their
commit message bodies.

---

## 3. Known sourcing gaps

- The npm snapshot (Section 1.2) reports its query as run "early in
  this session (shortly after the session's first message, timestamped
  2026-06-15 00:18:23 UTC)." The first git commit touching
  `research/src-qiwi/` (Section 2, row 1) is timestamped
  2026-06-15T03:36:04+00:00 — approximately 3 hours 18 minutes later.
  No source in this inventory documents what occurred in that
  interval.
- Excerpt 2 of `session-origin-2026-06-15.md` (the "Operating
  Instructions for SRC/QIWI" document) is marked
  `[PROVENANCE UNVERIFIED]` in its source file: its authorship, origin,
  and whether it predates the session are not established by any
  source in this inventory.
- The session-origin file describes itself as containing "a selection"
  of excerpts, "not the full transcript." The existence, content, or
  absence of transcript material between Excerpt 1 and Excerpt 2 is
  not established by any source in this inventory.
- Continuity of the six commits in Section 2 as part of a single,
  uninterrupted session is asserted only via the shared session URL
  string in each commit message; no source in this inventory
  independently verifies this.

---

## 4. `[SOURCE NOT FOUND]` markers

- Authorship/origin of Excerpt 2 ("Claude Code Operating Instructions
  for SRC/QIWI"): `[SOURCE NOT FOUND]`
- Repository state (presence/absence of files referenced by Excerpt 2,
  e.g. `PROJECT_SCOPE.md`, `predictions.md`, `cases.md`,
  `OBSERVATIONS.md`, `REMAINING_HANDOFF_RISKS.md`, `flowise_pilot.md`)
  at the time Excerpt 2 was received, as an independently captured
  snapshot: `[SOURCE NOT FOUND]`
- Session activity between 2026-06-15T00:18:23Z (npm query, per
  Section 1.2) and 2026-06-15T03:36:04Z (first `research/src-qiwi/`
  commit, per Section 2): `[SOURCE NOT FOUND]`
- Transcript content between Excerpt 1 and Excerpt 2 of
  `session-origin-2026-06-15.md`: `[SOURCE NOT FOUND]`

---

End of inventory. This file should not be treated as a source of
observations, predictions, or cases until reviewed separately through
the process described in `OBJECT_OF_STUDY.md`.
