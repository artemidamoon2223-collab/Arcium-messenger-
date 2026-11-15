# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-15 01:20 UTC, by a Claude Code cloud session

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `a68cea607d996935361de31daf844d5ebe179b7d` (merge of PR #184, 2026-11-14)

## Done
- 14 Nov (D-035): relay #179 (`9c36cf0`), #180 (`9b3f54f`), #181 (`b41050d`), #182 (`bc0dc19`); instruction files #183 (`bd5dfed`); tracker #184 R-9 and R-14 narrowed, both still OPEN (`a68cea6`; 12 check runs success on head `df296ba`).
- 14 Nov (D-021, D-023, D-025): #157–#166 merged; R-7 (b), R-10, R-17 fixed; delete contact (option C) merged.
- 14 Nov (D-026): #167 R-16 (`6d6acea`; 508 passed on its head), #168 tracker R-16 fixed (`33f93e7`).
- 14 Nov (D-031): #173 background receive (`d36a95e`), #175 R-19 off-chain circuit source (`fcabf55`), #174 option A for R-13 (`efd4c0e`), #176 CLAUDE.md circuit hash (`d764380`), #177 tracker (`41a0d8d`).
- 14 Nov (D-030): #171 R-18 (a)(c) (`92ad8eb`), #172 tracker R-18 partial (`ea7c3fe`).
- 14 Nov (D-028): #169 R-15 per-text cancel (`2cc79ff`; 515 passed locally), #170 tracker R-15 fixed (`4266537`).

## Open PRs (each needs the Owner's merge instruction naming it)
- #178 production relay design (docs only; head `e719564`).
- #185 five stale documentation lines aligned with `main` (docs only; head `2a87dea`).
- #186 two-day trial of a shorter CLAUDE.md, skills state rules not history (D-037; head `d8cd825`).

## Waiting for the Owner
- Production relay hosting: the Owner is renting a server (D-026); the code is merged (D-035); deploy with `docs/RELAY-DEPLOY.md`.
- Model choice: only the Owner switches to Fable 5.2 (D-034); ask, never pick it.
- Session recovery option B (after R-9 and X-6). Publishing the PSI circuit file before any deploy (R-19, `docs/HOME-DEPLOY.md` Step 1b). Release-signing key.
- R-18 (b) StrongBox / Keystore flags: needs a phone test.

## Next work (D-036 order; supersedes the D-014 line)
1. Relay on the Owner's server (`docs/RELAY-DEPLOY.md`) — needs the server.
2. A V2 relay in the emulator CI jobs — needs only the Owner's go-ahead (a workflow change).
3. Two phones through that relay, incl. background receive — needs phones.
4. Release build and signing — needs the Owner's decision on the key.
5. Phone checks: R-18 (b), H-8, F-9.
6. Protocol leftovers after Owner decisions: R-9 occupancy residual, X-6, option B.
7. Tor (F-15) → devnet (publish the circuit first) → PSI in the app.

## Needs devices
Two phones with a local relay (incl. background receive with the screen off); Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).

## Work package
Google Drive: `OPUS-WORK-PACKAGE-v3.md` (snapshot of 2026-11-14 00:02 UTC; this checkpoint is newer).
