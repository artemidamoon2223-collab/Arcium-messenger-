# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-10-21 01:15 UTC, by a Claude Code cloud session

## Resume procedure
1. The SessionStart hook on main (PR #123) prints both files automatically. Manual fallback: `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update, append to `decisions.md`, replace this file, commit only these two files, push normally (never force), and re-read both from GitHub.

## Baseline (re-verify)
- `main` = `483a66438a6d148ec624d3de530c79da0a16662f` (GitHub API, 2026-10-21 01:10 UTC)

## Done
- **PR #123 (SessionStart continuity hook): merged by the Owner** on 2026-10-20 at 17:11 UTC, as merge commit `483a664`.
  - Parents are `88e6957` and `7b9383f`. The tree `2bc6982` equals the PR head tree.
  - `.claude/hooks/continuity.sh` on main has sha256 `31250efe…8827`, the same as reviewed in the PR.
  - Push CI on `483a664`: Arcium CI run 39463860171, success. The Android workflows did not run; their path filters exclude `.claude/**` (SOURCE_VERIFIED in `.github/workflows/*.yml`).
  - First automatic load observed in the session of 2026-10-21 01:0x UTC: trigger `startup`, Recovery COMPLETE, STALE detected (checkpoint recorded `88e6957`). This is one real-CLI observation.
- **PR #122 (rustls 0.23.46, D-003): merged by the Owner** on 2026-10-20 at 15:05 UTC, as merge commit `88e6957`. Push CI 4 of 4 success.
- **C001 and C002: done** (D-001, D-002).
- **Continuity Phase 1: done** (D-006). Seed commit `6ac2d90`.

## Open
- **Debug APK** from run 39191179529, on `fb9cf32`. Expires 2026-10-26 at 02:54 UTC. The APK's own hash is NOT_VERIFIED. It predates rustls 0.23.46 and the hook.
- **Pixel manual tests P0–P12:** not started (UNVERIFIED).
- **Findings D-007…D-011:** open; each fix needs a separate Owner task.
- Older open PRs (#28, #29, #30, #41, #69, #82, #83): untouched; no decision recorded here.
- `decisions.md` has no entry for the PR #123 merge yet; adding one needs no code change but was not done in this session.

## Next authorized step
None. Waiting for the Owner's next task.

## Deferred (needs a MacBook)
- APK hash, signature and `.so` check.
- `connectedDebugAndroidTest` on the Pixel.
- F-9 run-as failure path.
- Master-key-loss check.
- Two phones with a local relay.
- The hook under macOS bash 3.2.
