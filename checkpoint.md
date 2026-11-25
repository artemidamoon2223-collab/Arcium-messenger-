# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-25 UTC (after D-152), by a Claude Code cloud session (013Fd9w25yw1w75yseYxbKXy)

## How to write to the Owner (D-086)
End each message with the Owner's next step in plain words and the exact text to type, or say that nothing is needed.

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `4f290cb18b1dec740bd895234671ddd6a14c22b8` (merge of PR #266, 2026-11-25)

## Done
- 25 Nov (D-112 to D-143, outside Arcium): Reliability System V1.2-review built in five rounds by separate Developer chats, reviewed by separate Reviewer chats, approved by the Owner (`./rs baseline`, D-142) and merged into reliability-system main as `70c287e` (D-143).
- 25 Nov (D-119): tracker #266 (F-15(b) FIXED; D-008, R-4 notes) merged as `4f290cb`.
- 24 to 25 Nov (D-112 to D-118, outside Arcium): Reliability System V1.1 imported unchanged into private `reliability-system` (`f3dafac`, PENDING_OWNER_APPROVAL); Reviewer chat verified it; V1.2-review adaptation planned and being built by a separate Developer chat; two-chat scheme with Claude Duet as console (D-118).
- 24 Nov (D-109, D-110): Tor step 3.2, #265 (Tor connector in core-transport; F-15(b) fixed in code) merged as `e690168`.
- 24 Nov (D-106 to D-108): tracker #263 merged as `49bd0bd`; Tor step 3.1 #264 (relay client connector seam) merged as `3840efc`.
- 24 Nov (D-104, D-105): Tor plan step 2.1, #262 (arti 0.48 in core-transport; sha2 0.11.1 accepted) merged as `c73bbbe`.
- 24 Nov (D-100): cleanups #260 (tracked `__pycache__` file removed, ignored) merged as `4dcffc3`, #261 (receive side-conflict comment) merged as `b1f6a37`.
- 24 Nov (D-098, D-099): Stage 5 decisions (1А attacker scope, 2А D-009 kept, 3А one process) recorded in `docs/S2-B2-DURABLE-MESSAGING.md`, #259 merged as `cf4f819`.
- 24 Nov (D-097): plan step 4.1, #258 (characterization tests of the four rollback cases D-009 left unexamined; tests only) merged as `4b03ed5`. Stage 4 closed.
- 24 Nov (D-095, D-096): plan step 3.1, #257 (fsync of the Android master-key blob before its key is used; tests and a kill scenario) merged as `5aaf7c5`.
- 22 Nov (D-093, D-094): plan step 2.4, #256 (two OS processes on one database commit each session generation once; tests only) merged as `5404c71`. Stage 2 closed.
- 22 Nov (D-091, D-092): plan step 2.3, #255 (64 seeded random sequences of messaging operations against a model, with storage faults; no disagreement; tests only) merged as `feccfe6`.
- 22 Nov (D-089, D-090): plan step 2.2, #254 (a sweep that fails every store operation of eight messaging operations in turn; no counterexample; tests only) merged as `afc5338`.
- 22 Nov (D-087, D-088): plan step 2.1, #253 (storage fault-injection layer behind the test-only feature `fault-injection`) merged as `0ff4794`.
- 22 Nov (D-085): plan step 1.4, #252 (tracker section on the process-kill tests, no status change) merged as `b7a9181`. Stage 1 closed.
- 22 Nov (D-084): plan step 1.3, #251 (kill test in the far pass, tests only) merged as `4ad3337`.
- 22 Nov (D-083): plan step 1.2, #250 (kill test between the relay accepting a receipt and the receipt leaving the outbox) merged as `031da1c`.
- 22 Nov (D-082): plan step 1.1, #249 (kill test between receipting an OPEN message and acknowledging it) merged as `c3f1c1b`.
- 22 Nov (D-078, D-081): #247 (comments of `artifact_committed`) merged as `74aece2`, #248 (kill tests between the two steps of `settle()`) merged as `cb3e5b3`; then `main` was `cb3e5b3`. The push run of CI on that commit was not read when this was written. Report `ARCIUM-RELIABILITY-ARCHITECTURE-001.md` is with the Owner (roadmap only).
- 21 to 22 Nov (D-077; outside the repository): Reliability System V1 built and used read-only on `256fed0`: audit pass 1 and a four-role diagnostic of durable state, no confirmed defect. Its V1.1 candidate is PENDING_OWNER_APPROVAL. Archives and hashes are in D-077; copies are on the Owner's Google Drive.
- 21 Nov (D-075, D-074; outside the repository): SE-001 and SI-001 prototypes; not installed.
- 21 Nov (D-070 to D-073): #240 to #246 (lib.rs/network.rs split, QC risk rules, tracker code locations); `main` = `256fed0`.
- 14 to 20 Nov (D-021 to D-069): PRs #157 to #239; each with its SHA is in `decisions.md`.

## Open PRs
- Arcium: none (#267, the pilot replay, closed unmerged, D-152; its branch `ccr-ee7f440a-77ozc8-pilot-replay-264` for the Owner to delete).
- reliability-system: PR #1 merged (D-143) as `70c287e`; main runs V1.2-review with the Owner's baseline (`./rs status` OK). Open: none. Its leftover branches were deleted by the Owner (D-145).
- Scratch branches: none left (D-145).

## Waiting for the Owner
- Later (D-148, D-149): when the work reaches testing Arcium Messenger, a full "memory dump" (handoff) of this Builder chat for a new chat "Arcium 1.1" (before it: `/skill-doctor` and a skills/plugins cleanup, D-150; the new chat attaches Arcium only); once the review process works, Claude Duet bot that reports progress and keeps a whiteboard with process diagrams.
- Production relay hosting: the Owner is renting a server (D-026); the code is merged (D-035); deploy with `docs/RELAY-DEPLOY.md`.
- Model choice: only the Owner switches to Fable 5.2 (D-034); ask, never pick it.
- Publishing the PSI circuit file before any deploy (R-19, `docs/HOME-DEPLOY.md` Step 1b). Release-signing key.
- R-18 (b) StrongBox / Keystore flags: needs a phone test.
- Reliability System V1.1 candidate (D-077): approval only through the permission prompt in the candidate's own folder (a computer with Claude Code, or a session opened on a repository that holds the candidate). Nothing of it is installed here.
- Reliability plan (D-080, approved 22 Nov): stages 0, 1 and 2 are closed. Step 3.1 merged (D-096); stage 4 closed (D-097). Stage 5 decided and recorded (D-098, D-099). Left: 3.2 (needs a physical phone).
- A choice in #257 to revisit before a release (D-095): a directory that cannot be synced blocks first start.
- Tor plan approved (D-102: T1A, T2A, T4A; T3 = В by template, reconfirm before 4.1). Step 1.1 done (D-103). Step 2.1 merged (D-105). Tracker #263 and step 3.1 #264 merged (D-108). Step 3.2 merged (D-110). Tracker #266 merged (D-119); next 4.1 (needs the Owner's decisions: T3, exit(1) policy, app size). Open for 4.1: exit(1) policy, app size, rsa in the app, provider install in the app, never TcpConnector for onion.

## Reliability plan (D-080, approved by the Owner, strictly in order)
Stage 0: done (D-081) → Stage 1: kill tests 1.1 OPEN handling, 1.2 receipt publish to `acknowledge_outgoing`, 1.3 far-skip pass, 1.4 tracker → Stage 2: storage fault injection (2.1 to 2.4) → Stage 3: Android master-key fsync (3.1), phone power-loss test (3.2) → Stage 4: rollback characterization tests → Stage 5: Owner decisions before a release. Stage 1 done (D-082 to D-085). Step 2.1 done (D-088). Step 2.2 done (D-090). Step 2.3 done (D-092). Step 2.4 done (D-094): stage 2 closed. Step 3.1 done (D-096). Step 4.1 done (D-097): stage 4 closed. Stage 5 decided and recorded (D-098, D-099). Left: 3.2 (needs a phone). Details: D-080.

## Next work (D-036 order; supersedes the D-014 line)
1. Relay on the Owner's server (`docs/RELAY-DEPLOY.md`) — needs the server.
2. A V2 relay in the emulator CI jobs — done (#187).
3. Two phones through that relay, incl. background receive — needs phones.
4. Release build and signing — needs the Owner's decision on the key.
5. Phone checks: R-18 (b), H-8, F-9; memory and time of #200 and #205 on a phone (scudo); far-skip cost (#209) on a phone.
6. Protocol: R-6 done (#222); R-21 32 chains done (#226); R-14/R-20 durable far-skip wait done (#227), tracker done (#228); R-9 keep/delete change deferred by the Owner (reconsider with the relay deployment); R-9 residuals (operator, V1, a sender counting its own messages, the far-wait write timing); R-14/R-20 residuals (over 100,000, way out a reset of option B; the delete after an accept is a separate write; the device clock); R-21 beyond 32 chains done (#230), tracker done (#231).
7. Tor (F-15) → devnet (publish the circuit first) → PSI in the app.

## Optimization plan (D-067, approved by the Owner, in order)
0, 6, 1 (#232), 2 (#233), 3 (#234), 4 (#235), 5 (environment): done → 7 split `lib.rs`/`network.rs` (D-070: #240, #241, #242): done. Possible follow-up, not started: QC rules to class identity.rs as IDENTITY and handshake/prekeys/responder as PROTOCOL. Follow-ups (D-068): relay comment and tracker notes done (#236); flaky net_limits test done (#237); unused `log` done (#238). core-transport's unused `anyhow`, `core-crypto`, `futures` done (#239, D-069).

## Needs devices
Two phones with a local relay (incl. background receive with the screen off); Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).

## Work package
Google Drive: `OPUS-WORK-PACKAGE-v3.md` (snapshot of 2026-11-14 00:02 UTC; this checkpoint is newer).
