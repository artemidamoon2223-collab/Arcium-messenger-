# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-11-14 06:10 UTC, by a Claude Code cloud session

## Resume procedure
1. The SessionStart hook prints both files. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update: append to `decisions.md`, replace this file, commit only these two files, push normally (never force), re-read both (`repo-change-protocol` §10).

## Baseline (re-verify)
- `main` = `42665370fa7fb344bc2ddfa1b16f17cb5c8b71f3` (merge of PR #170, 2026-11-14)

## Done
- 14 Nov (D-021, D-023, D-025): #157–#166 merged; R-7 (b), R-10, R-17 fixed; delete contact (option C) merged.
- 14 Nov (D-026): #167 R-16 (`6d6acea`; 508 passed on its head), #168 tracker R-16 fixed (`33f93e7`).
- 14 Nov (D-028): #169 R-15 per-text cancel (`2cc79ff`; 515 passed locally), #170 tracker R-15 fixed (`4266537`).

## Open PRs (each needs the Owner's merge instruction naming it)
- None.

## Waiting for the Owner
- Production relay: the Owner is renting a server (D-026); then authentication (R-9), TLS, persistence.
- Session recovery options A and B (C is merged).
- R-19: PSI circuit registered on chain, contrary to CLAUDE.md; decide before any deploy.
- Background receive (foreground service or push), release-signing key, R-18 items.

## Next work (D-014 order)
Production relay (after the server) → background receive → release signing → Tor, devnet, PSI.

## Needs devices
Two phones with a local relay; Pixel instrumentation; APK and `.so` signature check; H-8 on a release build; F-9 on a phone; devnet deploy at home (`docs/HOME-DEPLOY.md`).

## Work package
Google Drive: `OPUS-WORK-PACKAGE-v3.md` (snapshot of 2026-11-14 00:02 UTC; this checkpoint is newer).
