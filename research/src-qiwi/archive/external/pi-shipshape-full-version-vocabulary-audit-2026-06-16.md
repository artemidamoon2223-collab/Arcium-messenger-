# Archive: pi-shipshape Full Version Vocabulary Audit (2026-06-16)

- **Date:** 2026-06-16
- **Query time (approximate):** 2026-06-16T16:26 UTC
- **Source type:** External Snapshot + Live Audit
- **Registry source:** https://registry.npmjs.org/pi-shipshape
- **Status:** Raw Historical Material

---

## Published Version Space

A query of the npm registry on 2026-06-16 returned exactly 9 published
versions of `pi-shipshape`. Version numbers 0.1.0 through 0.1.6 are
not present in the registry and were never published.

The complete published version space is: **0.1.7 through 0.1.15**.

---

## Per-Version Record

| Version | Published    | shasum                                   |
|---------|--------------|------------------------------------------|
| 0.1.7   | 2026-06-12   | 128edb734b8ba0d06efb1b3f50d122f92f94cf1f |
| 0.1.8   | 2026-06-12   | 5291e95ab29a15bc15adc6ceb6f6d7b7bd137552 |
| 0.1.9   | 2026-06-12   | 81d7fc3822c9af2cf28833b873c61a6f3414ad78 |
| 0.1.10  | 2026-06-13   | 579db32310582abbd77645e87d69c9904840eb69 |
| 0.1.11  | 2026-06-14   | 4948639bf0166989cf90386d1bcf00896a6920f3 |
| 0.1.12  | 2026-06-14   | c44ff12371cbe70d2d498426be2d36b27b4b5056 |
| 0.1.13  | 2026-06-14   | b95290407d0b39ee3cfe797ff1c726215a0f394e |
| 0.1.14  | 2026-06-14   | 7b0b23b9f14a924899424810dc7d963183d31b76 |
| 0.1.15  | 2026-06-15   | 71a11c7ed7de5224d0f0322a7874044f7200da65 |

The shasum for 0.1.15 is consistent with the value recorded in
`archive/external/npm-pi-shipshape-2026-06-15.md`
(`71a11c7ed7de5224d0f0322a7874044f7200da65`).

---

## Vocabulary Audit

Each published version was downloaded from the npm registry, extracted,
and grepped for the following SRC/QIWI-specific vocabulary terms:

1. `INDETERMINATE`
2. `[SOURCE NOT FOUND]`
3. `OBSERVATIONS`
4. `predictions`
5. `cases.md`
6. `weakened`
7. `falsified`

### Results

All seven terms returned **zero matches** across all nine published
versions (0.1.7 through 0.1.15).

| Version | INDETERMINATE | [SOURCE NOT FOUND] | OBSERVATIONS | predictions | cases.md | weakened | falsified |
|---------|---------------|--------------------|--------------|-------------|----------|----------|-----------|
| 0.1.7   | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |
| 0.1.8   | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |
| 0.1.9   | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |
| 0.1.10  | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |
| 0.1.11  | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |
| 0.1.12  | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |
| 0.1.13  | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |
| 0.1.14  | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |
| 0.1.15  | 0             | 0                  | 0            | 0           | 0        | 0        | 0         |

---

## Note on Incidental Matches

A broader grep for generic English terms
(`case`, `evidence`, `observation`, `prediction`) returned a small
number of hits per version (5–12 across the full package). These are
incidental uses of common English words and do not represent
SRC/QIWI status vocabulary:

- `case` — appears in the Gherkin template ("Scenario: \<edge case\>"),
  in adapter prose ("cases the extension cannot detect"), and as a
  test fixture filename component in `assets-policy.md`.
- `evidence` — appears in blocker-escalation prose
  ("use blocker reports as evidence to update specs"), describing
  the Shipshape blocker-escalation workflow, not an evidence-tracking
  framework.

No version of pi-shipshape implements an observation log, a prediction
log, a case-filing system, or a status-transition framework of any kind.
The package implements a role-based agent workflow for software
development (Captain / Quartermaster / Crew Mate / Bosun roles,
Gherkin BDD specs, context-firewall, blocker escalation).

---

End of audit record.
