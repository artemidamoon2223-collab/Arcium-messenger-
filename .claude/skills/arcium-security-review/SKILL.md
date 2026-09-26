---
name: arcium-security-review
description: "Security review of a change to Arcium Messenger, run locally inside an ordinary Claude Code session before owner acceptance. Use for any change touching cryptography, protocol or wire formats, durable session state, identity and contact cards, the relay/network path, the Rust↔Kotlin FFI or Android lifecycle, the Arcium PSI program or circuit, CI workflows, dependencies or secrets — and whenever the owner asks for a security review of a branch, PR or commit range. Reads the complete diff and the surrounding source against this project's threat model. It is analysis, not proof; it needs no API key and authorizes nothing."
---

# arcium-security-review

## Status

Analysis aid. A review made with this skill is a careful reading of source,
sometimes backed by tests run for the purpose. It is not a proof, not an audit,
and not a substitute for tests or runtime evidence. A green test suite is not a
cryptographic proof, and "no findings" means only that this reading, at its
stated coverage, found none.

This skill authorizes nothing. Reviewing is read-only. Fixing a finding is a
separate task — and any change to cryptographic logic, protocol parameters or
wire formats needs its own explicit owner instruction (`CLAUDE.md`,
«Обращение с криптокодом»).

It runs in a normal Claude Code session. It needs no GitHub Actions job and no
API key.

## Use when

- a diff touches any area in `references/threat-checklist.md`;
- a security-sensitive change is about to go to the owner for acceptance;
- the owner asks for a security review of a branch, PR or commit range.

## Do not use when

- The question is engineering quality — scope, simplicity, verification. That
  is `engineering-code-review` (`references/karpathy-review.md`). On a
  security-sensitive change run both: they answer different questions.
- The question is clone, branch, PR or merge mechanics — `repo-change-protocol`.

When the diff touches durable session state, load `mbr-integration` as well: it
holds the evidence base for commit boundaries, outbox, ACK and rollback.

## Procedure

### 1. Fix the exact target

Record base and head as commit SHAs and review `BASE...HEAD`. With three dots
the diff starts at the merge base, so later commits on `main` do not appear in
it. A review of a moving branch reviews nothing in particular.

### 2. Read the complete change

- `git diff --name-status BASE...HEAD` gives every path, including deletions and
  renames.
- For every path, read its own diff: `git diff BASE...HEAD -- <path>`. A single
  diff of the whole change is cut when long.
- Then read every added or modified file at HEAD in full, from its first line
  to its last, in successive chunks if it is long. For a deleted file, read
  its full content at BASE (`git show BASE:<path>`) and search the tree for
  anything that still refers to it.
- Never review from a truncated diff, the first N lines, a file name or the PR
  description.
- Keep a coverage ledger built from tool output, not memory: for each path, how
  it was read. A path not read in full is not covered, and the review is
  `complete: no`.

### 3. Read the surrounding source

A diff shows what changed, not what the change touches. For each changed
function, type, constant or workflow step, read:

- its callers and callees, especially across crate and FFI boundaries;
- the specification that governs it — `docs/S2-B2-DURABLE-MESSAGING.md`,
  `docs/NET-MESSAGING.md`, the module's `//!` documentation — including what it
  says it does **not** provide;
- the tests that claim to cover it, to see what they actually assert;
- open findings on the same code in `docs/SECURITY-FINDINGS.md`.

### 4. Check every area the change touches

Map each change to the areas of `references/threat-checklist.md` and work
through each area it touches. Name the areas that do not apply and why. Use
only the threat classes recognised in `CLAUDE.md` («Анализ безопасности»).

### 5. Try to break it

For each candidate finding, write the concrete path: the attacker's position
(relay or network, peer, other app on the device, disk access, pull-request
author, dependency, on-chain caller), what they send or do, in what order, and
which property fails. If you cannot write that path, it is an open question,
not a finding.

Where a test can confirm or refute a candidate cheaply, write and run it in the
disposable clone and report the result. Do not commit it unless asked.

### 6. Report

Use the output block below. A verdict never says "secure" or "safe"; it says
what was found, at what coverage.

## Evidence labels

Every claim — a finding, "not affected", coverage — carries exactly one of the
four labels defined in `CLAUDE.md` («Границы доказательств»):
`SOURCE_VERIFIED` (with `path:line` at HEAD), `RUNTIME_VERIFIED` (with the
command and the test name or log line), `INFERRED` (with what it was inferred
from) or `NOT_VERIFIED` (with why, and what would verify it).

Do not promote a label. A passing test is `RUNTIME_VERIFIED` only for exactly
what that test asserts.

## Severity

- **CRITICAL** — plaintext or key disclosure, message forgery, or identity
  substitution that a remote party (relay, network, peer) can cause.
- **HIGH** — a remote party can permanently desynchronise or reset a session,
  get a replay accepted as new, or make the durable layer release output twice
  or lose a committed message.
- **MEDIUM** — needs local access, a specific interleaving or an unusual but
  reachable state; or a guarantee a specification or comment claims that the
  code does not provide.
- **LOW** — defence in depth: an unzeroized transient secret, a missing bound,
  a supply-chain pin.
- **INFO** — an observation or a test gap with no attack path of its own.

## What not to report

- Style, naming or performance with no security consequence — that is the
  engineering review.
- Weaknesses with no path in this code ("SHA-256 might be broken").
- Models outside the recognised threat classes (`CLAUDE.md` forbids them).
- A known open finding restated as new. Cite its tracker ID and say whether the
  change makes it better, worse or leaves it unchanged.

## Output

```
ARCIUM_SECURITY_REVIEW
target: <BASE_SHA>...<HEAD_SHA>
complete: <yes | no>
coverage: <every changed path: how it was read>
areas: <checklist areas the change touches; the others and why not>
findings:
  - <SEVERITY> | <title> | <path:line> | <attack path> | <label>
  (or: none)
known_findings: <tracker IDs the change affects, and how; or none>
tests_run: <command -> result; or none>
not_verified: <what could not be checked, why, and what would check it>
verdict: <one or two sentences: what was found, at what coverage>
ARCIUM_SECURITY_REVIEW_END
```

`complete: yes` requires every changed path read in full. Give the block to the
owner in the session report. Post it on a PR only when asked.

## References

- `references/threat-checklist.md` — the areas, where they live, and what to
  check in each.
