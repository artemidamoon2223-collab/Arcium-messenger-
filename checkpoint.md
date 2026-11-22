# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-22 UTC, by a Claude Code cloud session (013Fd9w25yw1w75yseYxbKXy)

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `256fed059062fd784227ccabd746a40b2b2a9622` (merge of PR #246, 2026-11-21)

## Done
- 22 Nov (D-078): draft PR #247 (comments of `artifact_committed`, head `d34eb7a`) and draft PR #248 (kill tests between the two steps of `settle()`, head `48fd19f`). Neither is merged. Report `ARCIUM-RELIABILITY-ARCHITECTURE-001.md` is with the Owner (roadmap only).
- 21 to 22 Nov (D-077; outside the repository): Reliability System V1 built and used read-only on `256fed0`: audit pass 1 and a four-role diagnostic of durable state, no confirmed defect. Its V1.1 candidate is PENDING_OWNER_APPROVAL. Archives and hashes are in D-077; copies are on the Owner's Google Drive.
- 21 Nov (D-075, D-074; outside the repository): SE-001 and SI-001 prototypes; not installed.
- 21 Nov (D-070 to D-073): #240 to #246 (lib.rs/network.rs split, QC risk rules, tracker code locations); `main` = `256fed0`.
- 14 to 20 Nov (D-021 to D-069): PRs #157 to #239; each with its SHA is in `decisions.md`.

## Open PRs
- #247 (draft): comments only; all 9 check runs success on `d34eb7a`. Waits for the Owner's merge instruction.
- #248 (draft): two test-only crash points and two kill tests; opened 22 Nov, re-check its CI.

## Waiting for the Owner
- Production relay hosting: the Owner is renting a server (D-026); the code is merged (D-035); deploy with `docs/RELAY-DEPLOY.md`.
- Model choice: only the Owner switches to Fable 5.2 (D-034); ask, never pick it.
- Publishing the PSI circuit file before any deploy (R-19, `docs/HOME-DEPLOY.md` Step 1b). Release-signing key.
- R-18 (b) StrongBox / Keystore flags: needs a phone test.
- Merge instructions for #247 and #248 (each needs the Owner naming the PR).
- Reliability System V1.1 candidate (D-077): approval only through the permission prompt in the candidate's own folder (a computer with Claude Code, or a session opened on a repository that holds the candidate). Nothing of it is installed here.
- Next step of the reliability roadmap (D-078): the Owner chooses; kill tests for OPEN handling, receipt publish and the far pass are still missing.

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
