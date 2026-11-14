# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-14 00:56 UTC, by a Claude Code cloud session

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `0a8dbd471763fa2298edf052c4991ec903ecf016` (merge of PR #160, 2026-11-14)

## Done
- 14 Nov, merged on the Owner's instruction (D-021), each with every check run success on its head: #159 (`1d29a0b`), #162 (`1b7e07d`), #157 (`3e4e0c3`), #158 (`ddca7cc`), #161 (`7e1a983`), #160 (`0a8dbd4`).
- `cargo test --workspace --locked` at `0a8dbd4`: 493 passed, 0 failed, 4 ignored; clippy `-D warnings` exit 0.
- Tracker at `0a8dbd4` holds R-13 … R-19; R-7 (b) and R-10 are fixed in code (tracker PR #164 records it).

## Open PRs (each needs the Owner's merge instruction naming it)
- #163 R-17: show a round's non-network errors on Android (D-022).
- #164 tracker: R-7 (b) and R-10 fixed.

## Waiting for the Owner
- Merges of #163 and #164.
- Session recovery option C / A / B (`docs/SESSION-RECOVERY-OPTIONS.md`).
- R-19: PSI circuit registered on chain, contrary to CLAUDE.md; decide before any deploy.
- Production relay (hosting cost), background receive (foreground service or push), release-signing key, R-18 items.

## Next work (D-014 order)
Session recovery (Owner's option) → R-15 → R-16 → production relay → background receive → release signing → Tor, devnet, PSI. After #163 merges, a tracker PR records R-17 as fixed.

## Needs devices
Two phones with a local relay; Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).

## Work package
Google Drive: `OPUS-WORK-PACKAGE-v3.md` (snapshot of 2026-11-14 00:02 UTC, before the merges; this checkpoint is newer).
