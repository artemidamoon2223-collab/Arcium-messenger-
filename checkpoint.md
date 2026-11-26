# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-26 UTC (after D-165), by the Builder chat "Arcium 1" (013Fd9w25yw1w75yseYxbKXy), handing over to a new Builder chat "Arcium 1.1"

## Read first
The session hook shows only the first 8,000 bytes of this file and almost nothing of `decisions.md`. The handoff from Arcium 1 (roles, how a change travels, the Arcium 2 review recipe, platform facts, open items) is entry **D-165**. Read it in full before any work:
`git fetch origin continuity && git show origin/continuity:decisions.md | sed -n '/^D-165 /,$p'`
Keep this file under about 7,000 bytes.

## How to write to the Owner (D-086)
Russian, plain words, result first, one step at a time. End each message with the Owner's next step and the exact text to type, or say that nothing is needed.

## Resume procedure
1. Read this file and D-165 (command above); older entries of `decisions.md` when a line here cites them.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10). Next entry: D-166.

## Baseline (re-verify)
- `main` = `623cdd995f06e96971ee54ee292fc6c977b3de15` (merge of PR #270, 2026-11-26)
- reliability-system (private) `main` = `70c287e`: Reliability System V1.2-review with the Owner's baseline (D-143).

## Open now
- Arcium: no open PR. reliability-system: no open PR; `review/pilot-267` and `review/pr-268` keep the two review records.
- For the Owner: delete the Arcium branch `ccr-ee7f440a-77ozc8-flush-nits`; say whether to archive the two idle review chats (#267 pilot, #268).
- Not done, planned by the Owner in this order: `/skill-doctor` (only the Owner can type it) and a skills/plugins cleanup (D-150); then the design of the new structure: notifications, status board, Claude Duet's role (D-154; proposals only in D-157, D-162, D-164). The Owner asked to be reminded to switch on Fable 5.2 before that design.
- Optional: the `audit/usage.py` double count in reliability-system (D-151).

## Recently done (older: `decisions.md`)
- 26 Nov (D-163): #270 (flush named in the timeout docs; test of a flush after the deadline) merged as `623cdd9`.
- 25 Nov (D-158, D-160): tracker #269 (R-4 note, no status change) merged as `fa37722`.
- 25 Nov (D-153 to D-156): #268 (flush bounded by the request deadline) merged as `fb34eba`: the first change through the full chain (Builder, fresh agent, Arcium 2, CI, the Owner).
- 25 Nov (D-112 to D-143): Reliability System V1.2-review built, reviewed, approved by the Owner and merged into reliability-system as `70c287e`.
- 24 Nov (D-104 to D-110, D-119): Tor steps 2.1 (#262), 3.1 (#264), 3.2 (#265) and trackers #263, #266 merged.
- 22 to 24 Nov (D-082 to D-099): the reliability plan's stages 0, 1, 2, 4, 5 and step 3.1 (#248 to #259).

## Waiting for the Owner
- Tor step 4.1 (wiring Tor into the app) needs decisions first: T3 to reconfirm (D-102), arti's exit(1) policy, app size, `rsa` in the app, provider install in the app, never TcpConnector for an onion address, a Tor-suited timeout, stream isolation.
- Production relay hosting: the Owner is renting a server (D-026); the code is merged (D-035); deploy with `docs/RELAY-DEPLOY.md`.
- Model choice: only the Owner switches to Fable 5.2 (D-034); ask, never pick it. Subagents and created chats inherit the model, so name a non-Fable one (D-165 §6).
- Publishing the PSI circuit file before any deploy (R-19, `docs/HOME-DEPLOY.md` Step 1b). Release-signing key.
- R-18 (b) StrongBox / Keystore flags: needs a phone test.
- Reliability plan (D-080): only step 3.2 is left (phone power-loss test, needs a physical phone).
- A choice in #257 to revisit before a release (D-095): a directory that cannot be synced blocks first start.
- R-9 keep/delete change deferred by the Owner (reconsider with the relay deployment).

## Next work (D-036 order)
1. Relay on the Owner's server (`docs/RELAY-DEPLOY.md`): needs the server.
2. Two phones through that relay, incl. background receive: needs phones.
3. Release build and signing: needs the Owner's decision on the key.
4. Phone checks: R-18 (b), H-8, F-9; memory and time of #200 and #205 on a phone; far-skip cost (#209) on a phone.
5. Protocol residuals: R-9 (operator, V1, a sender counting its own messages, the far-wait write timing); R-14/R-20 (over 100,000, the delete after an accept, the device clock).
6. Tor (F-15), step 4.1 next → devnet (publish the circuit first) → PSI in the app.

## Needs devices
Two phones with a local relay (incl. background receive with the screen off); Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).
