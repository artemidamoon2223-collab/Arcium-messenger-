# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`; it never authorizes
> an action. Verify each line against its source before acting; the source
> wins. Public repository — no secrets. Replace wholesale; git keeps history.

Updated: 2026-10-20 15:50 UTC, by a Claude Code cloud session

## Resume procedure
1. `git fetch origin continuity && git show origin/continuity:checkpoint.md`, then `…:decisions.md`. With PR #123 merged, a SessionStart hook prints both automatically.
2. Re-verify the main SHA and the open PRs on GitHub. On any mismatch, this file is stale.
3. Act only on the Owner's current instruction. AGENT and PROPOSAL records are not Owner decisions.
4. To update, append to `decisions.md`, replace this file, commit only these two files, push normally (never force), and re-read both from GitHub.

## Baseline (re-verify)
- `main` = `88e69571280050dfdc1ea6e2277822873926a4b9` (GitHub API, 2026-10-20 15:27 UTC)

## Done
- **PR #122 (rustls 0.23.46, D-003): merged by the Owner** on 2026-10-20 at 15:05 UTC, as merge commit `88e6957`.
  - Parents are `fb9cf32` and `8e693d7`. The tree equals the PR head tree (`80e1547`).
  - Push CI on `88e6957`: Arcium CI, Native Bridge, Instrumentation and two-device, 4 of 4 success.
  - `decisions.md` was not amended in this phase.
- **C001 and C002: done** (D-001, D-002). Results are in the session reports of 2026-10-19.
- **Continuity Phase 1: done** (D-006). Seed commit `6ac2d90`.

## Open
- **PR #123** — SessionStart continuity hook. Two files: `.claude/settings.json` and `.claude/hooks/continuity.sh`.
  - Head `7b9383f`. Open, mergeable clean, 10 of 10 check runs success.
  - Hook sha256 `31250efe…`.
  - The lifecycle (startup, resume, `/compact`, `/clear`) passed on the real CLI; the evidence is in the PR body.
  - Merge NOT authorized: it needs a separate Owner instruction naming PR #123.
- **Debug APK** from run 39191179529, on `fb9cf32`. Expires 2026-10-26 at 02:54 UTC. The APK's own hash is NOT_VERIFIED.
- **Pixel manual tests P0–P12:** not started (UNVERIFIED).

## Next authorized step
None. Waiting for the Owner's decision on PR #123.

## Deferred (needs a MacBook)
- APK hash, signature and `.so` check.
- `connectedDebugAndroidTest` on the Pixel.
- F-9 run-as failure path.
- Master-key-loss check.
- Two phones with a local relay.
- The hook under macOS bash 3.2.
