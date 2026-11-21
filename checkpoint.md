# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-21 UTC, by a Claude Code cloud session (013Fd9vyhG9UhoZ9sPkysoHR)

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `256fed059062fd784227ccabd746a40b2b2a9622` (merge of PR #246, 2026-11-21)

## Done
- 21 Nov (D-075; outside the repository, nothing here changed): SE-001, a skill-evolution prototype in `/var/se001` of that session's container. One candidate, new steps of one skill: validation 6/16 -> 10/16, sealed 5/24 -> 15/24 with no loss; an independent audit found the size overstated by a word-overlap check (strict recount 3/8 against 0/8 where the change acts). Not installed. Report and archive are with the Owner.
- 21 Nov (D-074; outside the repository): SI-001, a four-role pilot (Generator, Verifier, Meta-Check, Coach) in `/var/si001`: development cases 7/12 -> 10/12, sealed 5/8 -> 4/8, INCONCLUSIVE, candidate not promoted.
- 21 Nov (D-073): #245 tracker code locations of live rows after the split (`0b60dda`); #246 QC markers also by crypto words and algorithm constants, test code by place and build (`256fed0`).
- 21 Nov (D-072): #244 QC classes a new or ungated code file by the crypto and wire-format names its added code uses (a language-aware reader); every marked code file needs an owner-gated rule, checked by qc-unit (`43a5ae1`).
- 21 Nov (D-071): #243 QC risk rules classify the files that hold keys, wire formats, identities and records (mobile-ffi split files, Android identity/relay/store code, vendor/ as SUPPLY_CHAIN); test_qc_rules.py pins them (`e31a55a`).
- 21 Nov (D-070, step 7 of D-067): #240 lib.rs tests to src/tests/mod.rs (`bfad8c0`); #241 lib.rs code into error.rs, identity.rs, prekeys.rs, handshake.rs, responder.rs (`ed0cad6`); #242 network.rs internals into network/far_skip.rs, inbox.rs, mailbox.rs, outbox.rs, refusals.rs, tests.rs (`5a32f0c`). Pure moves: same 307 test names, Kotlin byte-identical; lib.rs 3,462 → 763 lines, network.rs 2,480 → 959.
- 20 Nov (D-069): #239 core-transport drops unused `anyhow`, `core-crypto`, `futures` (`8305ed6`); workspace and Android graphs unchanged.
- 20 Nov (D-068): #236 tracker note F-15/D-008 and relay comment, core-transport not a mobile-ffi dependency (`1d26e28`); #237 net_limits cut-round test no longer timing-dependent (`761cf43`); #238 unused `log` dependency of mobile-ffi dropped (`b2c2760`).
- 20 Nov (D-067 step 4): #235 hot-crate opt-level in test builds, CI test stores in memory (`6dd93b2`). With the warm cache: core-rust 11:25 → 6:28, tests step 7:09 → 2:45, clippy 59 s → 4 s; Android bridge build step 9:23 → 1:59.
- 20 Nov (D-067 steps 2, 3, 5): #233 CI `push` on `main` only (`f8b58b8`); #234 cargo cache in CI, saved on main only, cargo-audit not cached (`00ca884`); cloud environment "Arcium-messenger" with a prefetch setup script.
- 20 Nov (D-067 step 1): #232 drops the unused `core-transport` from `mobile-ffi` (`a777c87`): Android graph 390 → 131 packages, bridge build 9:23 → 5:23, `.so` smaller (TLS 1.2 code gone).
- 20 Nov (D-066): #230 R-21 beyond 32 chains, a message of a forgotten chain named on its second arrival (`7b6677f`); the one local test failure was a stale mutant binary, not a flake. Tracker #231 R-21 PARTIAL narrowed further, R-14 and R-9 notes (`ec6e00e`).
- 19 Nov (D-064, D-065): tracker #228 R-21, R-14, R-20 PARTIAL narrowed, R-9 note (`9c49e59`); #229 skills: reference links, the stored far-skip wait in the threat checklist, the relay design doc in the repo map (`0c9cdfd`).
- 19 Nov (D-064): #226 R-21 remembers 32 earlier receiving chains (`b476035`); #227 R-14/R-20 far-skip wait kept in the store across restarts (`2a6074f`); R-9 keep/delete change deferred by the Owner.
- 19 Nov (D-063): #225 skills refresh (`cb46ed7`): threat-checklist conflict rule, test locations, mutation check, merging a PR that is behind, tracker-text check, worktree as disposable copy, CLAUDE.md pointer to repo-change-protocol; QC loop unchanged.
- 19 Nov (D-062): #222 R-6 signed-prekey rotation (`553c3ba`): 7 days, and after a one-time-prekey change; previous key for one more period; V3 prekey record. #223 NET-MESSAGING qualifiers (`24c82c5`); #224 tracker R-6 PARTIAL and checklist (`d578295`).
- 19 Nov (D-060, D-061): #217 option B (`1cca4b8`), #218 R-21 older chains (`d983e8e`), #219 H-6 spare slot (`d1d2cde`), #220 R-24 card check + R-22 prune (`8bac3f3`); tracker #221 (`b26a483`).
- 14 to 18 Nov (D-021 to D-059): PRs #157 to #216; each with its SHA is in `decisions.md`.

## Open PRs
- None.

## Waiting for the Owner
- Production relay hosting: the Owner is renting a server (D-026); the code is merged (D-035); deploy with `docs/RELAY-DEPLOY.md`.
- Model choice: only the Owner switches to Fable 5.2 (D-034); ask, never pick it.
- Publishing the PSI circuit file before any deploy (R-19, `docs/HOME-DEPLOY.md` Step 1b). Release-signing key.
- R-18 (b) StrongBox / Keystore flags: needs a phone test.
- Reliability System V1 (D-076): the Owner will build it in a new session as a new, separate project; this repository is read-only for that task. The proposals for this repository in D-074 and D-075 are not applied.

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
