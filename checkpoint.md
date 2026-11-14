# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-14 01:30 UTC, by a Claude Code cloud session

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `de328a1b910dcad482775e153d3a8179eabeb10e` (merge of PR #156, 2026-11-13)

## Done
- 12–13 Nov: 23 PRs merged by the Owner (#126 … #156; tracker "Update 2026-11-13").
- `cargo test --workspace --locked` at `de328a1`: 491 passed, 0 failed, 4 ignored.
- 13–14 Nov: review of `de328a1`; the Owner delegated its open questions (D-013). Decisions D-014 … D-018.

## Open PRs (none merged; each needs the Owner's merge instruction naming it)
- #157 Android: remove unused stubs and Bluetooth permissions (R-7 b); independent review: no findings.
- #158 R-10: skip a missing history entry (493 passed; independent review: no findings).
- #159 `docs/SESSION-RECOVERY-OPTIONS.md` (options only).
- #160 tracker: R-13 … R-19, NET-MESSAGING corrections. Merge after or with #159.
- #161 docs: README, android/README, HOME-DEPLOY; delete PROJECT_CONTEXT.md.
- #162 skills and CLAUDE.md aligned with main.
After #157 and #158 merge: a tracker PR records R-7 (b) and R-10 as fixed.

## Waiting for the Owner
- Merges above.
- Session recovery option C / A / B (#159).
- R-19: PSI circuit registered on chain, contrary to CLAUDE.md; decide before any deploy.
- Production relay (hosting cost), background receive (foreground service or push), release-signing key, R-18 items.

## Next work (D-014 order)
R-17 (show local round errors) → session recovery (Owner's option) → R-15 → R-16 → production relay → background receive → release signing → Tor, devnet, PSI.

## Needs devices
Two phones with a local relay; Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).

## Work package
Google Drive: `OPUS-WORK-PACKAGE-v3.md` (v2 kept as `OPUS-WORK-PACKAGE.md`).
