# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-27 UTC (after D-187), by the Builder chat "Arcium 1.1" (013Fd9vynW9zatywT2BMTB1h), successor of "Arcium 1" (013Fd9w25yw1w75yseYxbKXy; D-165, D-169)

## Read first
The session hook shows only the first 8,000 bytes of this file and almost nothing of `decisions.md`. The handoff from Arcium 1 (roles, how a change travels, the Arcium 2 review recipe, platform facts, open items) is entry **D-165**, with the Owner's order in D-166 and corrections in D-167 and D-168 (the later entry wins). Read all four in full before any work:
`git fetch origin continuity && git show origin/continuity:decisions.md | sed -n '/^D-165 /,$p'`
Keep this file under about 7,000 bytes.

## How to write to the Owner (D-086)
Russian, plain words, result first, one step at a time. Since D-178: the Owner's eight answer rules (answer or step first, 2 minutes to read, "Что я опустил:", sparring before final plans); an adapted paste-in text was given (D-179): header "Твой шаг / Проверено / Сомнение" instead of the closing next-step line. The Owner's step and exact text go in the header, not at the end; a simple question gets a one-line answer.

## Resume procedure
1. Read this file and D-165 to D-168 (command above); older entries of `decisions.md` when a line here cites them.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10). Next entry: D-188.
5. At the start, `git fetch origin main` and compare `git rev-parse HEAD` with `origin/main`. If they differ, now or later, read CLAUDE.md and the skills from `origin/main`, not from the working tree.

## Baseline (re-verify)
- `main` = `cec924216aa101f88b9ee9eff4ce1ad020e20749` (merge of PR #272, 2026-11-27)
- reliability-system (private) `main` = `70c287e`: Reliability System V1.2-review with the Owner's baseline (D-143).

## Open now
- Arcium: no open PR. #272 (emulator test of background receive) merged (D-186). #271 (rules of the new scheme) merged (D-183); CLAUDE.md on `main` now holds the answer header, the other-chat rule and the review ladder. reliability-system: no open PR; `review/pilot-267` and `review/pr-268` keep the two review records.
- For the Owner: delete the Arcium branches `ccr-ee7f440a-77ozc8-flush-nits`, `docs/rules-new-scheme`, `test/bg-receive-e2e`, `test/bg-receive-e2e-mut-loop`, `test/bg-receive-e2e-mut-notify` (about 250 old branches exist in all, D-171). The two old review chats are archived (D-170).
- `/skill-doctor` is done (D-171). The Owner: "QC оставляем, решим на проектировании". Unanswered proposal: switch off 10 claude.ai skills unrelated to Arcium (only the Owner can).
- The design of the new structure (D-172, page https://claude.ai/artifact/JzLLzbnkCuVN13PYVi9nVD) is accepted: Р1 to Р9 (D-173). Status board published (D-174): https://claude.ai/artifact/WRCc8usLjLaR8urG9z8TAV; republish it whenever this file changes. Duet connected (D-175) and, by the Owner's change (D-176), works on request only: no schedule, no messages of its own; schedules switched off in Duet; no GitHub access, and a public page is not readable from Duet without a connection (D-177; the Builder advises against connecting it for now; question open). Step 5 dropped. Lock test done (D-184): a review chat created like ours has no add_repo tool, so it cannot attach Arcium; no reliability-system change needed. Rollout of D-172 done through step 8. Stage 2 running (D-187): the Owner installs the debug APK (artifact 15166682041 of run 45925883466, expires 2026-12-04) on their Android phone and reports. Each step on the Owner's word. The board shows New York time (D-181). Open: the push test (repeat); server and computer availability. The Owner has one Android phone, no second one.
- Optional: the `audit/usage.py` double count in reliability-system (D-151).

## Recently done (older: `decisions.md`)
- 27 Nov (D-185, D-186): #272 (emulator test of background receive, both mutations caught) merged as `cec9242`. D-184: lock test of review chats.
- 27 Nov (D-182, D-183): #271 (rules of the new scheme: answer header, other-chat rule, review ladder, status board) merged as `d753b71`.
- 26 Nov (D-172 to D-177): new working scheme designed and accepted; status board and Duet set up.
- 25 Nov (D-153 to D-156): #268 (flush bounded by the request deadline) merged as `fb34eba`: the first change through the full chain (Builder, fresh agent, Arcium 2, CI, the Owner).
- 25 Nov (D-112 to D-143): Reliability System V1.2-review built, reviewed, approved by the Owner and merged into reliability-system as `70c287e`.
- 24 Nov (D-104 to D-110, D-119): Tor steps 2.1 (#262), 3.1 (#264), 3.2 (#265) and trackers #263, #266 merged.

## Standing rule
Only the Owner switches to Fable 5.2 (D-034); ask, never pick it. Subagents and created chats inherit the caller's model, so always name a non-Fable one (D-165 §6, D-167).

## Waiting for the Owner
- Tor step 4.1 (wiring Tor into the app) needs decisions first: T3 to reconfirm (D-102), arti's exit(1) policy, app size, `rsa` in the app, provider install in the app, never TcpConnector for an onion address, a Tor-suited timeout, stream isolation.
- Production relay hosting: the Owner is renting a server (D-026); the code is merged (D-035); deploy with `docs/RELAY-DEPLOY.md`.
- Publishing the PSI circuit file before any deploy (R-19, `docs/HOME-DEPLOY.md` Step 1b). Release-signing key.
- R-18 (b) StrongBox / Keystore flags: needs a phone test.
- Reliability plan (D-080): only step 3.2 is left (phone power-loss test, needs a physical phone).
- A choice in #257 to revisit before a release (D-095): a directory that cannot be synced blocks first start.
- R-9 keep/delete change deferred by the Owner (reconsider with the relay deployment).

## Next work (from D-036, updated since; not a fresh Owner order, and no order against Tor 4.1 is decided)
1. Relay on the Owner's server (`docs/RELAY-DEPLOY.md`): needs the server.
2. Two phones through that relay, incl. background receive: needs phones.
3. Release build and signing: needs the Owner's decision on the key.
4. Phone checks: R-18 (b), H-8, F-9; memory and time of #200 and #205 on a phone; far-skip cost (#209) on a phone.
5. Protocol residuals: R-9 (operator, V1, a sender counting its own messages, the far-wait write timing); R-14/R-20 (over 100,000, the delete after an accept, the device clock).
6. Tor (F-15), step 4.1 next → devnet (publish the circuit first) → PSI in the app.

## Needs devices
Two phones with a local relay (incl. background receive with the screen off); Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).
