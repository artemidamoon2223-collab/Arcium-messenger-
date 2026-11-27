# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-27 UTC (after D-208), by the Builder chat "Arcium 1.1" (013Fd9vynW9zatywT2BMTB1h), successor of "Arcium 1" (013Fd9w25yw1w75yseYxbKXy; D-165, D-169)

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
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10). Next entry: D-209.
5. At the start, `git fetch origin main` and compare `git rev-parse HEAD` with `origin/main`. If they differ, now or later, read CLAUDE.md and the skills from `origin/main`, not from the working tree.

## Baseline (re-verify)
- `main` = `2578962fdc1a9a63aaa9dbcf3443a62ed915e6a5` (merge of PR #275, 2026-11-27)
- reliability-system (private) `main` = `70c287e`: Reliability System V1.2-review with the Owner's baseline (D-143).

## Open now
- Arcium: #276 open, draft: PR B2, the Settings route label and Tor state (D-206, D-207), head `cdad62d`; fresh review done (INFO only, fixed), CI green; waiting for «Мерж 276» or «Проверка 276». On the Owner's order (D-208): #277 core fixes (R275-1, R275-2, relay race), #278 tracker (Tor for onion relays), #279 security checklist (AGENT_CONTROL, Owner's word): reviewed, CI running, waiting for merge words. #275 (PR B1, Tor 4.1 core) merged as `2578962` after two fresh reviews and Arcium 2 APPROVE (D-202 to D-205). #274 (`TransportError::NeedsUpdate` for arti's SoftwareDeprecated bootstrap error) merged (D-201); no vendored arti-client («Р19 б», D-199, after D-198 corrected D-190); #273 closed unmerged. #272 (emulator test of background receive) merged (D-186). #271 (rules of the new scheme) merged (D-183); CLAUDE.md on `main` now holds the answer header, the other-chat rule and the review ladder. reliability-system: no open PR; `review/pilot-267` and `review/pr-268` keep the two review records.
- For the Owner: delete the Arcium branches `ccr-ee7f440a-77ozc8-flush-nits`, `docs/rules-new-scheme`, `test/bg-receive-e2e`, `test/bg-receive-e2e-mut-loop`, `test/bg-receive-e2e-mut-notify`, `tor/arti-no-exit`, `tor/needs-update`, `tor/step-4-1-core` (about 250 old branches exist in all, D-171). The two old review chats are archived (D-170).
- `/skill-doctor` is done (D-171). The Owner: "QC оставляем, решим на проектировании". Unanswered proposal: switch off 10 claude.ai skills unrelated to Arcium (only the Owner can).
- New working scheme (D-172, accepted D-173, page https://claude.ai/artifact/JzLLzbnkCuVN13PYVi9nVD) rolled out through step 8 (D-174 to D-186). Board https://claude.ai/artifact/WRCc8usLjLaR8urG9z8TAV, New York time (D-181): republish whenever this file changes. Duet works on request only, no GitHub (D-176, D-177). Review chats have no add_repo tool (D-184).
- Tor 4.1: all seven decisions taken (D-189 to D-195). PR A done (#274, D-201). PR B split: B1 #275 (rung 4), B2 the Android screen (D-202); then the tracker note. Stage 2 (app on the phone) when the Owner is home (D-188; APK artifact 15166682041 expires 2026-12-04). One Android phone, no second. Open: push test; server and computer.
- Optional: the `audit/usage.py` double count in reliability-system (D-151).

## Recently done (older: `decisions.md`)
- 27 Nov (D-202 to D-205): PR B1: #275 (onion relay only through embedded Tor) merged as `2578962`.
- 27 Nov (D-196 to D-201): PR A: #274 (NeedsUpdate) merged as `ff31f93`; vendored patch dropped after a corrected premise.
- 27 Nov (D-185, D-186): #272 (emulator test of background receive, both mutations caught) merged as `cec9242`. D-184: lock test of review chats.
- 27 Nov (D-182, D-183): #271 (rules of the new scheme: answer header, other-chat rule, review ladder, status board) merged as `d753b71`.
- 26 Nov (D-172 to D-177): new working scheme designed and accepted; status board and Duet set up.

## Standing rule
Only the Owner switches to Fable 5.2 (D-034); ask, never pick it. Subagents and created chats inherit the caller's model, so always name a non-Fable one (D-165 §6, D-167).

## Waiting for the Owner
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
