# Decisions — Arcium Messenger

> **Record, not authority.** An entry records what was decided or found and
> why. It never authorizes an action: authority comes only from the Owner's
> current instruction in the live session. Before relying on a technical
> claim, verify it against the evidence cited. This is a public repository:
> no secrets, keys or private data.

## Rules
- Append-only. To change a record, add a new entry. The only edit allowed to an
  old entry is its `Status` field, set to `SUPERSEDED by D-NNN`.
- `Kind` says who decided:
  - `OWNER` — the Owner instructed it.
  - `AGENT` — an engineering choice the agent made inside an Owner-authorized task.
  - `FINDING` — an observed fact or defect.
  - `PROPOSAL` — suggested, not approved.
  - `CORRECTION` — a fix to an earlier claim.
- An `AGENT` or `PROPOSAL` entry is never an Owner decision.
- Each claim cites evidence (SHA, PR, run ID, `path:line`) or is marked `UNVERIFIED`.
  `Owner message` sources live only in the session conversation; they cannot be
  fetched from GitHub.

Entry format: `D-NNN · date (UTC) · Kind · Status`, then What / Why / Evidence.

---

D-001 · 2026-10-19 · OWNER · DONE
- What: test campaign C001 under bounded authority: one Android CI dispatch; no code changes, commits, PRs or pushes.
- Evidence: Owner message "ARCIUM AUTONOMOUS TEST CAMPAIGN 001". Android CI run 39191179529 on `fb9cf32` (workflow_dispatch, success).

D-002 · 2026-10-19 · OWNER · DONE
- What: continue verification (C002) inside the C001 boundaries.
- Evidence: Owner message "Продолжай дальше". C002 changed nothing in the repository.

D-003 · 2026-10-19 · OWNER · ACTIVE
- What: bump rustls 0.23.45 → 0.23.46 as a separate task.
- Merge NOT authorized: it needs a separate Owner instruction naming PR #122.
- Evidence: Owner message "Делай отдельную задачу: обнови rustls до 0.23.46". PR #122, head `8e693d7`.

D-004 · 2026-10-19 · AGENT · ACTIVE (within D-003)
- What: in PR #122, keep the tooling-produced `Cargo.lock`, which includes one incidental edge: `tempfile` → `getrandom` 0.4.3 → 0.3.4.
- Rejected: hand-editing the lockfile to remove that edge.
- Why:
  - a no-op re-resolution of main (`cargo update -p rustls@0.23.45 --precise 0.23.45`) produces the same edge;
  - `tempfile` is a dev-dependency only;
  - the package count is 502 → 502.
- Evidence: the PR #122 body and commit `8e693d7` message (local runs, RUNTIME_VERIFIED in that session).

D-005 · 2026-10-20 · PROPOSAL · SUPERSEDED by D-006
- What: continuity memory on an orphan branch `continuity`, plus a SessionStart hook in `.claude/settings.json`.
- Evidence: the agent's proposal in the session of 2026-10-20.

D-006 · 2026-10-20 · OWNER · ACTIVE
- What: Phase 1 only:
  - the orphan branch `continuity`, holding exactly `decisions.md` and `checkpoint.md`;
  - pushes of these two files allowed;
  - no change to main, CLAUDE.md, hooks, settings or source;
  - no merge, no PR, no force-push.
- Hooks: NOT approved, deferred.
- Evidence: Owner message "ARCIUM CONTINUITY PHASE 1".

## Findings (engineering; fixing any of them needs a separate Owner task)

D-007 · 2026-10-19 · FINDING · OPEN
- What: master-key loss. If `master_key.blob` is missing, a new key is created, and onboarding then creates a new identity.
- Evidence: `android/app/src/main/kotlin/com/arcium/messenger/security/MasterKeyProvider.kt:42-58` at `fb9cf32`. The test `crates/mobile-ffi/src/lib.rs:1106` (`core_with_wrong_key_fails`) pins this behaviour. Tracker: F-9 limits.

D-008 · 2026-10-19 · FINDING · OPEN
- What: `TorTransport::new` has no bootstrap timeout. In a sandbox that blackholes connections, `new_fails_gracefully_without_tor` hung until a 300 s timeout.
- Impact: none today; Tor is unwired (F-15).
- Evidence: `crates/core-transport/src/lib.rs:22-26` at `fb9cf32`. The hang is RUNTIME_VERIFIED in the sandbox; its cause is INFERRED.

D-009 · 2026-10-19 · FINDING · KNOWN (F-10)
- What: rolling a single storage record back to an older ciphertext is accepted.
- Evidence: an external probe (s8) against `crates/core-storage` at `fb9cf32`, not committed. The tracker F-10 row already lists rollback as not covered.

D-010 · 2026-10-19 · FINDING · OPEN
- What: no phone-number normalization before `hash_contact`.
- Evidence: Rust, TS and Python agree on 60 vectors; `+7999…`, ` +7999…` and `7999…` give different hashes. Probe not committed. `hash_contact` has no caller yet.

D-011 · 2026-10-19 · FINDING · OPEN (low)
- What: `|| true` on the SDK-license step.
- Evidence: `.github/workflows/android-ci.yml:32` and `android-two-device-e2e.yml:90` at `fb9cf32`.

D-012 · 2026-10-06 · CORRECTION · ACTIVE
- What: pin MCP merge calls with `expectedHeadSha`, not `sha`. The PR #120 merge used `sha`.
- Evidence: UNVERIFIED from GitHub; this is the agent's own record of its earlier session. Merge commit `e0e825c` has the expected parents.
