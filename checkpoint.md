# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-19 (evening) UTC, by a Claude Code cloud session

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `553c3ba59434ae9ecd9c4c8fb0495bc0b9a88f8d` (merge of PR #222, 2026-11-19)

## Done
- 19 Nov (D-062): #222 R-6 signed-prekey rotation (`553c3ba`): 7 days, and after a one-time-prekey change; previous key for one more period; V3 prekey record.
- 19 Nov (D-060, D-061): #217 option B (`1cca4b8`), #218 R-21 older chains (`d983e8e`), #219 H-6 spare slot (`d1d2cde`), #220 R-24 card check + R-22 prune (`8bac3f3`); tracker #221 (`b26a483`).
- 18 Nov (D-059): #215 R-9 a V2 relay stores a SEND only from the envelope's authenticated sender (`c2acfb6`); #216 tracker R-9 OPEN, narrowed further (`38cc867`).
- 18 Nov (D-058): #213 R-6 kept unrotated, one-time prekey replaced when an own session wins a simultaneous start (`9b95493`); #214 tracker R-6 ACCEPTED, one case fixed (`6d9c628`).
- 18 Nov (D-057): #211 X-6 a handshake without a one-time prekey is never answered (`f452eb3`); #212 tracker X-6 FIXED, R-6 revisit due (`c8489d9`).
- 18 Nov (D-056): #209 R-14 far skip up to 100,000 after a 10-minute wait (`7755efd`); #210 tracker R-14, R-20 PARTIAL (`88969c6`).
- 18 Nov (D-055): #207 R-21 GONE notice for the current receiving chain (`6e00a7f`); #208 tracker R-21 PARTIAL (`b729891`).
- 17 Nov (D-054): #205 R-22 `last_sent` pruned after every round (`3f0cf9f`); #206 tracker R-22 FIXED (`003af23`).
- 17 Nov (D-053): #203 R-24 X3DH refuses low-order keys (`3767d94`); #204 tracker R-24 FIXED (`cf8d96e`).
- 17 Nov (D-052): #202 test catches a weaker copy-room threshold (`1c5b2c1`).
- 17 Nov (D-051): #199 R-25 one-pass eviction (`5061041`), #200 H-6 reserved capacity (`e4e2313`), #201 tracker R-25 FIXED, H-6 narrowed (`d52395e`).
- 17 Nov (D-050): #197 `when_to_use` in review skills (`54be38a`), #198 tracker R-23 FIXED (`9d76423`).
- 17 Nov (D-049): #196 R-23 fixed, `shift_remove` keeps skipped-key order (`b1257df`).
- 17 Nov (D-048): shorter CLAUDE.md kept (trial of D-037 closed).
- 17 Nov (D-047): branch protection on `main` requires 6 Arcium CI checks and up-to-date branches (Owner; screenshots).
- 17 Nov (D-046): weekly retro; #195 three review/process rules in skills (`1e9e464`).
- 16 Nov (D-045): #194 tracker R-23, R-24 (C004 NEW-1, NEW-2) (`546f5c2`); claude.ai project texts refreshed.
- 16 Nov (D-044): #192 CLAUDE.md done-when / two attempts / fresh reviewer incl. CI (`c15cb0c`); #193 advisory CI check and merge/deploy guard hook (`b142ed7`).
- 15 Nov (D-043): #191 tracker, H-7 OPEN — narrowed (`06c990c`).
- 15 Nov (D-041): classification of the project; #188 `npm ci` (`d6bb4bb`), #189 H-7 partial (`14e77a0`), #190 tracker R-20 … R-22 and status words (`79be252`).
- 15 Nov (D-040): #187 V2 relay in the two-device emulator job, neutral link banner (`3f104e9`).
- 15 Nov (D-039): #185 docs aligned (`c97cfd2`), #186 shorter CLAUDE.md trial started (`6f3a5e6`), #178 relay design doc (`2f9327b`).
- 14 Nov (D-035): relay #179 (`9c36cf0`), #180 (`9b3f54f`), #181 (`b41050d`), #182 (`bc0dc19`); instruction files #183 (`bd5dfed`); tracker #184 R-9 and R-14 narrowed, both still OPEN (`a68cea6`; 12 check runs success on head `df296ba`).
- 14 Nov (D-021, D-023, D-025): #157–#166 merged; R-7 (b), R-10, R-17 fixed; delete contact (option C) merged.
- 14 Nov (D-026): #167 R-16 (`6d6acea`; 508 passed on its head), #168 tracker R-16 fixed (`33f93e7`).
- 14 Nov (D-031): #173 background receive (`d36a95e`), #175 R-19 off-chain circuit source (`fcabf55`), #174 option A for R-13 (`efd4c0e`), #176 CLAUDE.md circuit hash (`d764380`), #177 tracker (`41a0d8d`).
- 14 Nov (D-030): #171 R-18 (a)(c) (`92ad8eb`), #172 tracker R-18 partial (`ea7c3fe`).
- 14 Nov (D-028): #169 R-15 per-text cancel (`2cc79ff`; 515 passed locally), #170 tracker R-15 fixed (`4266537`).

## Open PRs
- #223 `docs/r6-bounds-precision`: NET-MESSAGING qualifiers of the R-6 bounds (docs only); merge first.
- #224 `docs/tracker-r6-rotation`: tracker R-6 PARTIAL and checklist lines.
- Both: CI, then merge only on the Owner's instruction naming them.

## Waiting for the Owner
- Production relay hosting: the Owner is renting a server (D-026); the code is merged (D-035); deploy with `docs/RELAY-DEPLOY.md`.
- Model choice: only the Owner switches to Fable 5.2 (D-034); ask, never pick it.
- R-6 signed-prekey rotation: design approved, P = 7 days, clock risk documented (D-062); merged as #222 (`553c3ba`); docs #223 and tracker #224 open. Publishing the PSI circuit file before any deploy (R-19, `docs/HOME-DEPLOY.md` Step 1b). Release-signing key.
- R-18 (b) StrongBox / Keystore flags: needs a phone test.

## Next work (D-036 order; supersedes the D-014 line)
1. Relay on the Owner's server (`docs/RELAY-DEPLOY.md`) — needs the server.
2. A V2 relay in the emulator CI jobs — done (#187).
3. Two phones through that relay, incl. background receive — needs phones.
4. Release build and signing — needs the Owner's decision on the key.
5. Phone checks: R-18 (b), H-8, F-9; memory and time of #200 and #205 on a phone (scudo); far-skip cost (#209) on a phone.
6. Protocol: R-6 done (#222); R-9 residuals (operator, V1, a sender counting its own messages); R-14/R-20 residuals (over 100,000; a durable far-skip wait); R-21 beyond four chains.
7. Tor (F-15) → devnet (publish the circuit first) → PSI in the app.

## Needs devices
Two phones with a local relay (incl. background receive with the screen off); Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).

## Work package
Google Drive: `OPUS-WORK-PACKAGE-v3.md` (snapshot of 2026-11-14 00:02 UTC; this checkpoint is newer).
