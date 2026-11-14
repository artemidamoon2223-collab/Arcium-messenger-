# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-14 02:58 UTC, by a Claude Code cloud session

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `3ac0af5bc218e792b9c01e7a419ab6dff807d4f9` (merge of PR #164, 2026-11-14)

## Done
- 14 Nov, merged on the Owner's instruction (D-021), each with every check run success on its head: #159 (`1d29a0b`), #162 (`1b7e07d`), #157 (`3e4e0c3`), #158 (`ddca7cc`), #161 (`7e1a983`), #160 (`0a8dbd4`).
- `cargo test --workspace --locked` at `0a8dbd4`: 493 passed, 0 failed, 4 ignored; clippy `-D warnings` exit 0.
- Tracker at `0a8dbd4` holds R-13 … R-19; R-7 (b) and R-10 are fixed in code (tracker PR #164 records it).
- 14 Nov, merged on the Owner's instruction (D-023): #163 R-17 (`63b606d`), #164 tracker R-7 (b), R-10, R-17 fixed (`3ac0af5`); every check run success on each head.

## Open PRs (each needs the Owner's merge instruction naming it)
- #165 delete a contact (session recovery option C, D-024), head `826d2b5`: 507 passed locally; all 20 check runs success (two-devices green on one re-run after an SDK download failure); independent review MEDIUM and LOW fixed in the PR.

## Waiting for the Owner
- Session recovery options A and B (C is being implemented, D-024).
- R-19: PSI circuit registered on chain, contrary to CLAUDE.md; decide before any deploy.
- Production relay (hosting cost), background receive (foreground service or push), release-signing key, R-18 items.

## Next work (D-014 order)
Session recovery C (#165) → tracker PR for R-13/R-14 mitigation after #165 merges → R-15 → R-16 → production relay → background receive → release signing → Tor, devnet, PSI.

## Needs devices
Two phones with a local relay; Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).

## Work package
Google Drive: `OPUS-WORK-PACKAGE-v3.md` (snapshot of 2026-11-14 00:02 UTC, before the merges; this checkpoint is newer).
