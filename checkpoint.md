# Checkpoint — Arcium Messenger

> **Snapshot, not authority.** True only as of `Updated`. It never authorizes an
> action. Before acting on any line, verify it against its source; where they
> differ, the source wins and this file is stale. Public repository — no
> secrets. Replace this file wholesale on each update; git history keeps the
> old versions.

Updated: 2026-10-20 (UTC), by a Claude Code cloud session

## Manual read / resume procedure
1. Read this file and `decisions.md` from the `continuity` branch.
   - `git fetch origin continuity`
   - `git show origin/continuity:checkpoint.md`
   - `git show origin/continuity:decisions.md`
   - No clone? Open `https://github.com/artemidamoon2223-collab/Arcium-messenger-/tree/continuity`.
2. Re-verify the baseline on GitHub:
   - the main SHA;
   - the state of each open PR listed below.
   - If anything differs, treat this file as stale.
3. Check every claim you rely on against its cited evidence.
4. Act only on the Owner's current instruction. Nothing here grants authority. A `PROPOSAL` or `AGENT` record is not an Owner decision.
5. To update:
   - append to `decisions.md`; replace this file;
   - commit only these two files to `continuity`;
   - push normally (never force);
   - re-read both from GitHub.

## Active goal
ARCIUM CONTINUITY PHASE 1 (D-006): this branch and these two files only.

## Baseline (re-verify)
- `main` = `fb9cf323840b94d55395084fbb4aa9697e8e4b7d` (GitHub API, 2026-10-20 03:42 UTC).

## Campaign status
- **C001 — DONE** (D-001), on `fb9cf32`.
  - Rust: 428 pass / 0 fail / 3 ignored; clippy clean. TS: 17 + 13 passing.
  - UniFFI plaintext check: PASS. Ratchet probe: 8/8 pass; its mutation control failed 6/8 as designed.
  - Android CI run 39191179529: success.
  - Evidence: the session report of 2026-10-19. Probes were not committed.
- **C002 — DONE** (D-002).
  - Storage probe 8/8 (controls failed 3/8 and 1/8 as designed). Hash parity 60/60.
  - Findings D-007…D-011. A fresh cargo-audit found RUSTSEC-2026-0346..0349 in rustls 0.23.45.
  - Evidence: the session report of 2026-10-19.

## Open items
- **PR #122** (D-003, D-004): rustls 0.23.46, `Cargo.lock` only.
  - Head `8e693d7`. Open, not merged; mergeable_state clean; 16/16 check runs success.
  - Merge NOT authorized: it needs a separate Owner instruction naming PR #122.
  - Evidence: GitHub API, 2026-10-20 03:42 UTC. Arcium CI run 39270863386 (fresh audit database, 1338 advisories).
  - Until #122 merges, any other PR to main is expected to fail the cargo-audit step (INFERRED).
- **Debug APK** `arcium-messenger-debug`:
  - artifact 12160825327, run 39191179529;
  - zip `sha256:8e06b21ae7c067909a773e5fe592c6e9f98461b600a22403558a100426e32c5f`;
  - expires 2026-10-26 02:54 UTC;
  - the APK's own hash is NOT_VERIFIED: the download was blocked in the sandbox.
- **Pixel manual tests P0–P12:** not started (UNVERIFIED that none were run outside the session).

## Blockers
- The cloud sandbox has no Android SDK, adb or device.
- Artifact bytes cannot be downloaded (blob host 403).

## Next authorized step
None. Phase 1 is complete once this branch is verified. Phase 2 (hooks) and the merge of PR #122 each need a separate Owner instruction.

## Deferred (needs MacBook)
- APK hash, signature and `.so` check;
- `connectedDebugAndroidTest` on the Pixel;
- F-9 failure path via `run-as`;
- master-key-loss check;
- local relay with two phones.
