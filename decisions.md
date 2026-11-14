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

D-007 · 2026-10-19 · FINDING · SUPERSEDED by D-020
- What: master-key loss. If `master_key.blob` is missing, a new key is created, and onboarding then creates a new identity.
- Evidence: `android/app/src/main/kotlin/com/arcium/messenger/security/MasterKeyProvider.kt:42-58` at `fb9cf32`. The test `crates/mobile-ffi/src/lib.rs:1106` (`core_with_wrong_key_fails`) pins this behaviour. Tracker: F-9 limits.

D-008 · 2026-10-19 · FINDING · SUPERSEDED by D-020
- What: `TorTransport::new` has no bootstrap timeout. In a sandbox that blackholes connections, `new_fails_gracefully_without_tor` hung until a 300 s timeout.
- Impact: none today; Tor is unwired (F-15).
- Evidence: `crates/core-transport/src/lib.rs:22-26` at `fb9cf32`. The hang is RUNTIME_VERIFIED in the sandbox; its cause is INFERRED.

D-009 · 2026-10-19 · FINDING · SUPERSEDED by D-020
- What: rolling a single storage record back to an older ciphertext is accepted.
- Evidence: an external probe (s8) against `crates/core-storage` at `fb9cf32`, not committed. The tracker F-10 row already lists rollback as not covered.

D-010 · 2026-10-19 · FINDING · SUPERSEDED by D-020
- What: no phone-number normalization before `hash_contact`.
- Evidence: Rust, TS and Python agree on 60 vectors; `+7999…`, ` +7999…` and `7999…` give different hashes. Probe not committed. `hash_contact` has no caller yet.

D-011 · 2026-10-19 · FINDING · SUPERSEDED by D-020
- What: `|| true` on the SDK-license step.
- Evidence: `.github/workflows/android-ci.yml:32` and `android-two-device-e2e.yml:90` at `fb9cf32`.

D-012 · 2026-10-06 · CORRECTION · ACTIVE
- What: pin MCP merge calls with `expectedHeadSha`, not `sha`. The PR #120 merge used `sha`.
- Evidence: UNVERIFIED from GitHub; this is the agent's own record of its earlier session. Merge commit `e0e825c` has the expected parents.

D-013 · 2026-11-13 · OWNER · ACTIVE
- What: the Owner delegated the eight open questions of the review of `main` @ `de328a1` to the agent ("реши эти вопросы по возможности", "чтобы всё было как в швейцарских часах"), within the `CLAUDE.md` limits: no merge, no protocol or crypto change without a separate Owner decision, no expense.
- Evidence: Owner message in session `013Fd9w11HPCwF53H2tPuKpt`, 2026-11-13, about 23:30 UTC.

D-014 · 2026-11-13 · AGENT (under D-013) · ACTIVE
- What: priority. The production relay (authentication R-9, TLS, persistence) and background receive come before PSI, Tor and devnet.
- Why: a release build cannot send or receive at all (only debug builds accept a relay; `android/app/build.gradle.kts`, `RelaySettings.kt`), and the app calls no PSI code (`ArciumCore.submitPsiQuery` throws).
- Evidence: the review report in the session above.

D-015 · 2026-11-13 · AGENT (under D-013) · ACTIVE
- What: R-7 (b) and stubs. Remove the Bluetooth permissions; delete `BluetoothMeshManager`, `SolanaClient` (and the `SOLANA_RPC_URL` build field) and `ContactRepository`; keep `MessageRepository` (two tests use it). PR #157.
- Merge NOT authorized: it needs an Owner instruction naming the PR.

D-016 · 2026-11-13 · AGENT (under D-013) · ACTIVE
- What: R-10, fixed: a missing history number is skipped by the record build, pages and the summary. PR #158.
- Evidence: the new test fails on `de328a1` ("storage error: key not found") and passes on the PR head; `cargo test --workspace --locked` 492 passed, 0 failed; clippy `-D warnings` exit 0 (RUNTIME_VERIFIED in a disposable clone).

D-017 · 2026-11-13 · AGENT (under D-013) · ACTIVE
- What: session recovery is recorded as options only (C: delete a contact completely; A: raise a conflict only after the peer's first message authenticates; B: peer-authenticated replacement). PR #159. Choosing and implementing one is an Owner decision (protocol).

D-018 · 2026-11-13 · AGENT (under D-013) · ACTIVE
- What: the QC family (`qc-*` skills and agents, `.claude/qc/`) is kept unchanged.
- Why: it is manual-only and costs nothing unused; removing an Owner-merged tool needs a reason. Revisit at a weekly retro if it stays unused.

D-019 · 2026-11-13 · FINDING · OPEN
- What: R-13 (a false conflict, once resolved, dead-ends a conversation) and R-14 (more than `MAX_SKIP` lost messages in one sending chain stop that direction for good), both RUNTIME_VERIFIED by probes at `de328a1` (not committed). R-15 … R-18 SOURCE_VERIFIED. R-19: the PSI circuit is registered on chain (`arcium-psi/programs/arcium-psi/src/lib.rs:42`, `None`), contrary to `CLAUDE.md`.
- Evidence: tracker PR #160.

D-020 · 2026-11-13 · CORRECTION · ACTIVE
- What: the statuses of D-007 … D-011 as of `main` @ `de328a1`, from `docs/SECURITY-FINDINGS.md`:
  - D-007: Android start-up half closed (PR #133); the Rust-level `Ok(None)` and the lack of a recovery flow stay open (F-9).
  - D-008: fixed (PR #137, bootstrap bound 120 s).
  - D-009: decided (no rollback resistance in v1; PR #138).
  - D-010: decided and implemented (E.164; PR #139).
  - D-011: fixed (A-4, PR #135).
- Evidence: tracker sections "Update 2026-11-06", "Update 2026-11-12", "Update 2026-11-13".

D-021 · 2026-11-14 · OWNER · DONE
- What: merge #157, #158, #159, #160, #161, #162 with normal merge commits, each only once every check on its current head is green, #159 before #160. Next: a tracker PR and R-17.
- Evidence: Owner answer of 2026-11-14 in session `013Fd9w11HPCwF53H2tPuKpt` ("Да, все шесть", "Трекер + R-17"). Merged at 00:29–00:50 UTC, each pinned with `expectedHeadSha`; `main` = `0a8dbd4`.

D-022 · 2026-11-14 · AGENT (under D-021) · ACTIVE
- What: R-17 fixed in PR #163 (`RelayLink.Online.problem`, shown in the banner); tracker PR #164 records R-7 (b) and R-10 as fixed. Neither merge is authorized by D-021.

D-023 · 2026-11-14 · OWNER · DONE
- What: merge #163, then the small tracker PR recording R-17 as fixed; "я тебе разрешаю, делай все" for the next steps of the plan.
- Evidence: Owner message of 2026-11-14 in session `013Fd9w11HPCwF53H2tPuKpt`. #163 merged as `63b606d`; R-17 folded into tracker PR #164, merged as `3ac0af5`; every check run success on each head.

D-024 · 2026-11-14 · AGENT (under D-023) · ACTIVE
- What: session recovery option C ("delete contact": forget a peer in any session state, in one transaction; pending outgoing marked abandoned; seen/send-id kept). Chosen over A and B as the smallest, local, user-triggered step (`docs/SESSION-RECOVERY-OPTIONS.md`). No wire, record-layout or crypto change. Merge of its PR is not authorized by D-023.

D-025 · 2026-11-14 · OWNER · DONE
- What: merge #165 ("Мержим, делай дальше"); tracker PR #166 merged under the same instruction. Next: R-16 (PR #167; its merge needs the Owner's instruction naming it).

D-026 · 2026-11-14 · OWNER · DONE
- What: "сделаем первое, второе" (the R-16 tracker PR, then R-15); the production relay waits until the Owner rents a server. Then "мёрдж #167".
- Evidence: Owner messages of 2026-11-14 in session `013Fd9w11HPCwF53H2tPuKpt`. #167 merged as `6d6acea` (18 check runs success on head `fa7a0c9`); tracker PR #168 (R-16 fixed) merged as `33f93e7` (12 check runs success on head `c4680ef`); both pinned with `expectedHeadSha`.

D-027 · 2026-11-14 · AGENT (under D-026) · ACTIVE
- What: R-15 as a per-text user cancel (`NetworkMessenger::cancel_text`, new `ChatEntryState::Cancelled`, stored code 6; `publish_pending` abandons a cancelled text instead of sending it). No automatic give-up. No wire, protocol or crypto change; entry layout and `ENTRY_VERSION` unchanged; a build without code 6 cannot read such an entry (downgrade). PR #169; its merge needs the Owner's instruction naming it.
- Evidence: 515 passed, 0 failed locally on `6d6acea` + the PR; clippy `--all-targets` exit 0; independent review: one MEDIUM race and a JVM-test import error, both fixed in the PR.

D-028 · 2026-11-14 · OWNER · DONE
- What: "мёрдж #169" (R-15, per-text cancel). Tracker PR #170 (R-15 fixed) merged under the approved pattern (small tracker PR after a fix merges).
- Evidence: Owner message of 2026-11-14 in session `013Fd9w11HPCwF53H2tPuKpt`. #169 merged as `2cc79ff` (20 check runs success on head `5632ab6`); #170 merged as `4266537` (12 check runs success on head `7c01287`); both pinned with `expectedHeadSha`.

D-029 · 2026-11-14 · OWNER · ACTIVE
- What: answers to the agent's questions on the open decisions (no server needed for these):
  - R-19: switch the PSI circuit to an off-chain source (URL + hash), as CLAUDE.md requires. Publishing the circuit file (e.g. a GitHub release) still needs a separate Owner approval.
  - Session recovery: option A now (a handshake beside our own unconfirmed session no longer raises a conflict until its first message authenticates); option B later, after the production relay (R-9) and X-6.
  - Background receive: an opt-in foreground service; no push, no FCM.
  - R-18: delegated ("чтобы всё соответствовало нашему проекту"); agent choice: (a) FLAG_SECURE and (c) dataExtractionRules now (PR #171); (b) StrongBox / Keystore flags deferred to a phone test (emulators lack StrongBox; unlocked-device or user-auth flags would block background receive).
  - Release signing key: not decided; agent recommendation: held only by the Owner, signing done locally.
- Evidence: Owner answers of 2026-11-14 in session `013Fd9w11HPCwF53H2tPuKpt`. Each item is its own PR; every merge still needs the Owner's instruction naming the PR.

D-030 · 2026-11-14 · OWNER · DONE
- What: "мёрдж #171" (R-18 a FLAG_SECURE, c dataExtractionRules). Tracker PR #172 (R-18 partial) merged under the approved small-tracker-PR pattern.
- Evidence: #171 merged as `92ad8eb` (18 check runs success on head `bd596d0`); #172 merged as `ea7c3fe` (12 check runs success on head `2686b5f`); both pinned with `expectedHeadSha`.

D-031 · 2026-11-14 · OWNER · DONE
- What: "173, 175, 174 и CLAUDE.md … Исполняй": merge #173 (background receive), #175 (R-19 off-chain circuit source), #174 (session recovery option A, approving its two extra steps: the R-1 refusal from the beside state and the conflict flag moved to bit 16), and correct CLAUDE.md on the circuit hash. CLAUDE.md fix PR #176 and tracker PR #177 merged under that instruction.
- Evidence: #173 merged as `d36a95e` (18 check runs success on head `cb38d45`); #175 as `fcabf55` (12 on `361d5d1`); #174 as `efd4c0e` (19 on `0a75fa7`; 532 passed locally at `b2d1088`); #176 as `d764380` (12 on `cf96fc1`); #177 as `41a0d8d` (12 on `5c7e534`); all pinned with `expectedHeadSha`. Each code PR had an independent review whose findings were fixed in the PR.
- Remaining: publishing the PSI circuit file (needs the Owner's approval at deploy time); R-13 replay residual; phone tests for background receive.
