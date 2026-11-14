# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-14 04:34 UTC, by a Claude Code cloud session

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `0b8c28e64e02f4ff7bffc90e6875d6e11670019e` (merge of PR #166, 2026-11-14)

## Done
- 14 Nov, merged on the Owner's instruction (D-021), each with every check run success on its head: #159 (`1d29a0b`), #162 (`1b7e07d`), #157 (`3e4e0c3`), #158 (`ddca7cc`), #161 (`7e1a983`), #160 (`0a8dbd4`).
- `cargo test --workspace --locked` at `0a8dbd4`: 493 passed, 0 failed, 4 ignored; clippy `-D warnings` exit 0.
- Tracker at `0a8dbd4` holds R-13 … R-19; R-7 (b) and R-10 are fixed in code (tracker PR #164 records it).
- 14 Nov, merged on the Owner's instruction (D-023): #163 R-17 (`63b606d`), #164 tracker R-7 (b), R-10, R-17 fixed (`3ac0af5`); every check run success on each head.

- 14 Nov, merged on the Owner's instruction (D-025): #165 delete a contact (`6714921`; 507 passed at that commit), #166 tracker: delete-contact way out of R-13/R-14 (`0b8c28e`).

## Open PRs (each needs the Owner's merge instruction naming it)
- #167 R-16: refuse a retransmitted handshake again after the interval; head `fa7a0c9`; 508 passed locally; CI green; independent review: no findings. After it merges, a tracker PR records R-16 as fixed.

## Waiting for the Owner
- Session recovery options A and B (C is merged).
- R-19: PSI circuit registered on chain, contrary to CLAUDE.md; decide before any deploy.
- Production relay (hosting cost), background receive (foreground service or push), release-signing key, R-18 items.

## Next work (D-014 order)
R-16 (#167) → R-15 → production relay → background receive → release signing → Tor, devnet, PSI.

## Needs devices
Two phones with a local relay; Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).

## Work package
Google Drive: `OPUS-WORK-PACKAGE-v3.md` (snapshot of 2026-11-14 00:02 UTC, before the merges; this checkpoint is newer).
