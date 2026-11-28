# Security Findings Tracker — Arcium Messenger

**Reconciled against `main` @ `087b9c8c550e0b96d7b451d3f953e4860cd7765c` (the merge of PR #103), 2026-09-29.**
The previous snapshot was `main` @ `492c5d1f6385ddf698cf210ec29f0d67fb6a1d8f`, 2026-07-19.
F-17 additionally keeps its own 2026-07-28 closure record, with a re-check note at the end of it.
**Partially updated against `main` @ `090bb17b38c80ab0cf66a8de9ed22f0d92034336`, 2026-11-06:** the F-9 master-key-lifecycle residual only (PR #133). See "Update 2026-11-06: master-key loss at start-up"; every other row keeps the SHA it cites.
**Partially reconciled against `main` @ `7455da8440521a14bbb09baf8d646243a8b5d6c6`, 2026-11-06:** the PRs merged since PR #121 and the leads D-007…D-011 only. See "Reconciliation 2026-11-06"; every other row keeps the SHA it cites.
**Rows added 2026-11-12 against `main` @ `a4a8479`:** D-008, D-010, R-1 … R-7, X-5, X-6 (see "Update 2026-11-12"); no earlier row was changed. R-6 is recorded as accepted by the Owner.
**Statuses and rows added 2026-11-13 against `main` @ `c2c967c`:** R-1 … R-5, R-7 (a, c, d), A-4 and D-009 recorded as fixed or decided; new rows R-8 … R-12 (see "Update 2026-11-13"); no earlier row was changed.
**R-12 recorded as fixed 2026-11-13 against `main` @ `c07bf36`** (PR #154; see "Update 2026-11-13: R-12 fixed"). Only the R-12 row gained a dated note; no other row was changed.
**Rows added 2026-11-14 against `main` @ `de328a1`:** R-13 … R-19, and notes on R-7 (b) and R-10 (fix in review) (see "Update 2026-11-14"); no earlier row was changed.
**R-7 (b), R-10 and R-17 recorded as fixed 2026-11-14 against `main` @ `63b606d`** (PRs #157, #158, #163; see "Update 2026-11-14: R-7 (b), R-10 and R-17 fixed"), with a note on F-15 (a); no earlier row was changed.
**Way out of R-13 and R-14 recorded 2026-11-14 against `main` @ `6714921`** (PR #165, delete a contact; see "Update 2026-11-14: delete a contact"); no earlier row was changed.
**R-9 and R-14 narrowed, R-8 noted, 2026-11-14 against `main` @ `bd5dfed`** (production relay, PRs #179–#182; see "Update 2026-11-14: production relay"); no earlier row was changed.
**Rows R-20 … R-22 and the status words added 2026-11-15 against `main` @ `3f104e9`** (see "Update 2026-11-15: R-20 … R-22 and status words"), with a note on H-7's anchors; no earlier row was changed.
**H-7 narrowed 2026-11-15 against `main` @ `79be252`** (PR #189; see "Update 2026-11-15: H-7 narrowed"); no earlier row was changed.
**Rows R-23 and R-24 (C004 NEW-1, NEW-2) added 2026-11-16 against `main` @ `b142ed7`** (see "Update 2026-11-16: R-23 and R-24"), with a note on R-21; no earlier row was changed.
**R-23 recorded as fixed 2026-11-17 against `main` @ `b1257df`** (PR #196; see "Update 2026-11-17: R-23 fixed"), with notes on R-21 and H-6; no earlier row was changed.
**R-25 added as fixed and H-6 narrowed 2026-11-17 against `main` @ `e4e2313`** (PRs #199, #200; see "Update 2026-11-17: R-25 fixed, H-6 narrowed"), with a note on R-21; no earlier row was changed.
**R-24 recorded as fixed 2026-11-17 against `main` @ `3767d94`** (PR #203; see "Update 2026-11-17: R-24 fixed"); no earlier row was changed.
**R-22 recorded as fixed 2026-11-17 against `main` @ `3f0cf9f`** (PR #205; see "Update 2026-11-17: R-22 fixed"); no earlier row was changed.
**R-21 recorded as partial 2026-11-18 against `main` @ `6e00a7f`** (PR #207; see "Update 2026-11-18: R-21 partial"); no earlier row was changed.
**R-14 and R-20 recorded as partial 2026-11-18 against `main` @ `7755efd`** (PR #209; see "Update 2026-11-18: R-14 and R-20 partial"); no earlier row was changed.
**X-6 recorded as fixed 2026-11-18 against `main` @ `f452eb3`** (PR #211; see "Update 2026-11-18: X-6 fixed"), with a note on R-6; no earlier row was changed.
**R-6 revisited 2026-11-18 against `main` @ `9b95493`** (PR #213; see "Update 2026-11-18: R-6 revisited"): still ACCEPTED, one case fixed; no earlier row was changed.
**R-9 narrowed further 2026-11-18 against `main` @ `c2acfb6`** (PR #215; see "Update 2026-11-18: R-9 narrowed further"): still OPEN; no earlier row was changed.
**Option B, R-21, H-6, R-24 and R-22 recorded 2026-11-19 against `main` @ `8bac3f3`** (PRs #217–#220; see "Update 2026-11-19: option B, R-21, H-6, R-24, R-22"): R-13 PARTIAL with a way out by a reset on the waiting device, R-6 reopened, R-21 narrowed further, R-22's remaining cost and R-24's remainder (a) fixed, H-6 narrowed further; no earlier row was changed.
**R-6 recorded as partial 2026-11-19 against `main` @ `553c3ba`** (PR #222; see "Update 2026-11-19: R-6 signed prekey rotated"): the signed prekey is rotated, the key-compromise route bounded; no earlier row was changed.
**R-21, R-14 and R-20 narrowed, R-9 noted, 2026-11-19 against `main` @ `2a6074f`** (PRs #226, #227; see "Update 2026-11-19: R-21 32 chains, R-14 wait kept across restarts"): all still PARTIAL or OPEN; no earlier row was changed.
**R-21 narrowed further, R-14 and R-9 noted, 2026-11-20 against `main` @ `7b6677f`** (PR #230; see "Update 2026-11-20: R-21 beyond 32 chains"): all still PARTIAL or OPEN; no earlier row was changed.
**F-15 and D-008 noted 2026-11-20 against `main` @ `6dd93b2`** (PR #232; see "Update 2026-11-20: core-transport not a mobile-ffi dependency"): `core-transport` is no longer a `mobile-ffi` dependency; no status changed and no earlier row was changed beyond a dated note.
**Code locations after the split noted 2026-11-21 against `main` @ `43a5ae1`** (PRs #240–#242; see "Update 2026-11-21: code locations after the split"): the anchors of R-21, R-14 (and so R-20), R-9, R-6, R-13 and H-7 in `crates/mobile-ffi/src/lib.rs` and `network.rs` moved, to the new files or to new lines in the same files; no status changed and no earlier row was changed beyond a dated note.
**Process-kill tests noted 2026-11-22 against `main` @ `4ad3337`** (PRs #247–#251; see "Update 2026-11-22: process-kill tests inside a round"): five more places in a network round (six crash points) have a test that kills the process there, with notes on R-14 and R-21, and #247 corrected two doc comments; no status changed and no earlier row was changed beyond a dated note.
**arti 0.48 in core-transport noted 2026-11-24 against `main` @ `c73bbbe`** (PR #262; see "Update 2026-11-24: arti 0.48 in core-transport"): F-15, D-008, A-3.5, H-9 and the 2026-11-20 "Not a row" paragraph noted (PR #262 removed the RUSTSEC-2025-0009 ignore); no status changed and no earlier row was changed beyond a dated note.
**F-15(b) recorded as fixed 2026-11-24 against `main` @ `e690168`** (PRs #264, #265; see "Update 2026-11-24: Tor connector in core-transport"): the Tor client uses the directory it is given; D-008 and R-4 noted, with notes on the rows and sections that said F-15(b) still holds; no earlier row was changed beyond a dated note.
**R-4 noted 2026-11-25 against `main` @ `fb34eba`** (PR #268; see "Update 2026-11-25: flush bounded by the request deadline"): the relay client sets the write timeout before every flush to what is left of the request deadline; no status changed and no earlier row was changed beyond a dated note.
**F-15, D-008 and R-4 noted 2026-11-27 against `main` @ `2578962`** (PRs #274, #275; see "Update 2026-11-27: Tor for onion relays"): the Tor transport has a caller, for a relay at an onion address only; no status changed and no earlier row was changed beyond a dated note.
**F-12, F-15 and D-008 noted 2026-11-28 against `main` @ `cdbf9d3`** (PRs #276, #277; see "Update 2026-11-28: Tor route in Settings and core fixes"): Settings labels the route (through Tor or not) by a Kotlin copy of the core's rule, the Kotlin Tor stub is gone, a start that panics pauses like any failed start, and a malformed development address is tried nowhere; no status changed and no earlier row was changed beyond a dated note.

## What this file is — and is not

This is a dated **snapshot** of security-finding status, written by reading source.
It is not a live source of truth, and being checked in does not make it one: a row is
only as current as the commit it cites, and the previous snapshot had drifted away from
`main` in several rows by the time this one was written. **If a row and the source
disagree, the source is right and the row is stale.**

Rules for readers, and for reviews that use this file:

1. Before relying on a row, re-check the `path:line` and the test it cites against the
   exact commit you are reviewing. Line numbers move; cite them at your own target SHA.
2. A row records what was verified and what was not. `FIXED` is about the code paths the
   row names, not about the underlying property in general.
3. `arcium-security-review` treats this file as a list of leads and as the place where
   accepted residuals are recorded. It does not replace reading the source.
4. A status change lands in a tracker PR of its own, after the code fix
   (`repo-change-protocol` §9).

### Evidence basis of this reconciliation

- Every current-status claim below cites the source of `main` @ `087b9c8` (`path:line`),
  a test that passes there, or CI evidence. Tests: `cargo test -p core-crypto -p
  core-storage` (90 and 35 passed, 0 failed) and seven named `mobile-ffi` tests, all run
  locally on this commit on 2026-09-29. CI: Arcium CI run 36488538945 on `087b9c8`,
  job `core-rust` — core-crypto 90, core-protocol 107, core-storage 35 (+2 ignored),
  core-transport 5 (+1 ignored), mobile-ffi 116, relay 17, doctests 4, 0 failed; the
  clippy and `cargo audit` steps ended `success`; job `arcium-test` reported `6 passing`.
- The corrections to F-2, F-8, F-11, F-12 and F-13 and the A-1…A-3 entries follow an
  owner-supplied audit, ARCIUM-SECURITY-STATE-RECONCILIATION-001, whose report is **not
  stored in this repository**. It is therefore not cited as evidence: each of those claims
  was re-derived from source here, and where a claim needed a stated limit (F-8, F-10,
  F-13, F-15) the limit is written in the row.
- Statements about `hmac`, `hkdf` and `sha2` cite the crate sources at the versions CI
  resolved (`hmac 0.12.1`, `hkdf 0.12.4`, `sha2 0.10.9`, `digest 0.10.7`; core-rust job
  log of Arcium CI run 36484817324, the CI run of this tree before the merge). `Cargo.lock`
  was git-ignored (`.gitignore:2`), so the repository itself did not pin those versions (A-3.7 tracks it).
  Statements about `@arcium-hq/client` cite version 0.10.4, pinned in
  `arcium-psi/tests/package-lock.json:77-78`.

### Where the finding definitions come from

- Full original definitions of F-1 … F-17 live in
  [`docs/SECURITY-REVIEW-2026-06-deep.md`](./SECURITY-REVIEW-2026-06-deep.md), the
  2026-06-09 deep review, imported verbatim as a historical snapshot. Its status language
  reflects 2026-06-09, not today. The review defines 17 findings (1 HIGH, 5 MED, 6 LOW,
  5 INFO).
- The A-series (A-1, A-2, A-3) and the follow-ups (H-series) below were opened after that
  review; their definitions are in the rows themselves and in the pull requests they cite.

### Status vocabulary

- **FIXED** — the vulnerable code named in the row is gone from `main`; evidence is a
  `path:line` and/or a passing test. Read the row's scope note before citing it.
- **PARTIAL** — part is fixed, part remains; both sides are cited.
- **NOT-FIXED** — the vulnerable code the review quoted is still on `main`.
- **VERIFIED-BENIGN** — the concern was checkable from source and the source does not
  support it, at the version named in the row. Nothing was changed.
- **NEEDS-HOME / CANNOT-VERIFY-FROM-CODE** — cannot be settled by reading source (needs
  devnet, a device, an open network, or library internals not available here).
- *(corrected 2026-09-29)* marks a row whose status or scope differs from the 2026-07-19
  snapshot.

---

## F-series findings (from the 2026-06 deep review)

| ID | Sev | One-line (from the review) | Status | Evidence (`main` @ `087b9c8` unless noted) |
|----|-----|----------------------------|--------|-----------------------------------------------|
| **F-1** | HIGH | Ratchet state mutated before AEAD auth → an unauthenticated attacker permanently desyncs a session | **FIXED** *(wording corrected 2026-09-29)* | Original fix commit `1ae5f72`. Now: `DoubleRatchet::decrypt` (`crates/core-crypto/src/ratchet.rs:205-222`) takes a snapshot (`:211`, `snapshot` at `:261`) and restores it on any error (`:217-218`, `restore` at `:277`). Since A-3 (PR #103) `RatchetSnapshot` (`:360`) has **no `Drop` impl**: its key fields are `Zeroizing`/`StaticSecret` and wipe themselves when the snapshot is dropped or moved back. (The 2026-07-19 row cited a zeroizing `Drop` on `RatchetSnapshot`; that no longer exists.) Tests `forged_unknown_dh_message_does_not_mutate_state` (`:520`) and `forged_ciphertext_reusing_skipped_key_header_does_not_consume_key` (`:578`) pass — run locally and in CI `core-rust` on `087b9c8`. |
| **F-2** | MED | X3DH: no binding between the Ed25519 `signing_pk` and the X25519 `identity_pk` | **FIXED** *(corrected 2026-09-29)* | `crates/core-crypto/src/x3dh.rs`: the signature covers `signed_prekey_object_v1` (`:69-82`), a 116-byte object of domain `arcium/x3dh-spk/v1` (`:17`), version, suite, **`identity_dh_pk`**, `signing_pk` and `signed_prekey_pk`; `verify_signed_prekey_v1` (`:91-101`) uses `verify_strict`. Substituting the X25519 identity under a signature made for another one fails: tests `substituted_identity_dh_key_is_rejected` (`x3dh.rs:288`) and, at the FFI boundary, `bundle_with_substituted_identity_key_is_rejected` (`mobile-ffi/src/lib.rs:1771`) pass. AD is still initiator identity then responder identity (`x3dh.rs:137-139`, `:176-178`). **Scope:** the signing key still arrives inside the bundle it authenticates; what makes it trustworthy is the pinned contact card (`CONTACT_CARD_V1` carries both keys, `mobile-ffi/src/contacts.rs:17`), i.e. the out-of-band comparison. This row does not claim anything about the card exchange itself. |
| **F-3** | MED | PSI zero-padding produces false-positive matches on padding slots | **FIXED — merged (PR #118)** *(updated 2026-10-06; was NOT-FIXED)* | Evidence at `main` @ `ed5737c` (merge commit `ed5737c9916b8bbaf4b73d26d6b418a1d4454d30`, PR HEAD `aba4c14`). **Fix:** both encrypted inputs carry their number of real entries, `count: BaseField25519` (`arcium-psi/encrypted-ixs/src/lib.rs:32`, `:38`). `real_slots` (`:54`) accepts a count only if it equals one of 0…10 (`:59`), so no other field value is reduced into range, and marks slots `i < count` as real. Only real server slots are compared (`:90`), and a slot matches only if it is a real client slot and both counts are valid (`:94`). For any other count `MatchResult.valid` (`:48`) is false and no match is set. A real hash of 0 is compared like any other value. The client still pads with 0, which no longer matters (`arcium-psi/tests/src/client.ts:34-47`). More than 10 contacts or a hash outside `u64` is an error (`:36`, `:40`). `decryptResult` (`:114-146`) checks the request count, a result of 11 × 32 bytes, a nonce equal to the request nonce + 1, every value exactly 0 or 1, the validity flag and every padding slot. It throws on an invalid result instead of reading it as "no matches" (`:140`). **ABI:** `SharedEncryptedStruct<10>` → `<11>` for both inputs (`programs/arcium-psi/src/lib.rs:61-62`, `:211-212`; the counts are `ciphertexts[10]`, `:96`, `:110`; `#[check_args]` `:58`) and for the result (`:149-150`). **`CIRCUIT_HASH`:** `dd3bda7c6101e45f765165bfb01327313300758f0e3ae59ad79beace94b7b919` (`tests/src/scenarios.test.ts:21`). Arcium CI fails unless it is the hash of the circuit it built (`.github/workflows/arcium-ci.yml:103-109`). **Verified (RUNTIME_VERIFIED)** in Arcium CI run 37400401705 on `ed5737c` (push, attempt 1, success): (a) arcium-build: the built `psi_intersect.arcis.ir` hashes to `dd3bda7c…b919` (1,307,059,902 ACUs). The compiled circuit, run through Arcis mock MPC (`encrypted-ixs/src/lib.rs:107-271`), passes 6 tests: empty sets and count bounds, a real zero hash, padding never matching, duplicates, and counts 11, 255, 256, `u64::MAX`, `u128::MAX` and p−1 failing closed on either side. (b) ts-crypto: `crypto.test.ts` 17 passing. (c) arcium-test: three real MPC computations on localnet, each on its own fresh localnet, decrypted to the expected matches `[1,0,1,0,…,1]`; to `[0,0,1,0,…,1]` for a real zero hash with every padding collision; and to all zeros for client count 11, which `decryptResult` rejects. **Executor-reported only:** the negative controls in PR #118 (circuit masks removed, an invalid count accepted, client checks removed — all caught on disposable copies) were not reproduced for this row. **Limits:** (1) Strict 0/1 decoding is not authentication. RescueCipher is unauthenticated counter mode, and a 0→1 ciphertext change passes (test `does not detect a ciphertext changed from 0 to 1`, `crypto.test.ts:168`). A wrong-key result is rejected only if some value decodes outside 0/1, as in the tested sample. (2) The server's count is as trustworthy as the server (F-4). Results are still not delivered to a client (F-14). (3) Only the zero-padding probe is closed: no general secrecy of the server's cardinality is claimed, and ordinary `u64` hash collisions remain possible. (4) `submit_psi_query` was 1231 of 1232 bytes as a v0 transaction with the MXE lookup table. That is the observed size of the tested path, not a guarantee for other account sets or transaction forms. (5) Each MPC scenario runs on a fresh localnet to work around an Arx node race (arcium 0.10.4): a later computation for the same definition can stay queued. This is a CI workaround, not an upstream fix. (6) Devnet or production behaviour, and whether any circuit is deployed, are NOT_VERIFIED. |
| **F-4** | MED | `submit_psi_query`: the server dataset is supplied and encrypted by the caller, no on-chain anchoring | **NOT-FIXED** | `arcium-psi/programs/arcium-psi/src/lib.rs:57` — `server_data: SharedEncryptedStruct<10>` is still an instruction argument; the only validation is a non-zero encryption key (`:66-69`). No account, PDA or commitment binds it. (Full impact is `NEEDS-HOME`; the code state is unambiguous.) |
| **F-5** | MED | Unpinned GitHub Actions and package installs in workflows holding `ANTHROPIC_API_KEY` | **FIXED — merged (PR #116)** *(updated 2026-10-05; was PARTIAL)* | Evidence at `main` @ `fbf7243`. **Earlier:** every workflow that held `ANTHROPIC_API_KEY` — `karpathy-review.yml`, `pi-review.yml`, `security-review.yml` — was removed in commit `17682c5` (LLM reviews now run locally; `CLAUDE.md` «Ревью и CI» forbids LLM keys in workflows), and `graphify.yml` before that (PR #62); no file under `.github/` references the key, `claude-code-action`, `claude-code-security-review` or `pi-coding-agent`. That closed the secret-exposure path; the pinning concern stayed open. **PR #116** (merge commit `fbf72434be25d4e47ef706125c8e3eee301a01bd`, PR HEAD `596160a`) closed it: every external `uses:` in `.github/workflows/` and `.github/actions/` is `owner/repo@<40-hex commit SHA> # vX.Y.Z` — 30 references, none by tag, branch or short SHA; the 5 `./.github/actions/uniffi-android-bridge` references stay local. For each action kept at its release the SHA is the commit its previous tag pointed at: checkout v4.4.0, setup-node v4.4.0, upload-artifact v4.6.2, github-script v7.1.0, android-emulator-runner v2.38.0, setup-arcium v0.10.4. setup-java v4, deprecated upstream, became v5.7.0 (`b6effb0`), and `actions/checkout@v3` in `monthly-backup.yml` became v4.4.0 (`:26`). The archived `actions/create-release` and `actions/upload-release-asset` are gone: `monthly-backup.yml:45-64` runs `gh release create --draft` with the ZIP, requires the asset's exact name, size and `uploaded` state, and only then `gh release edit --draft=false`; `GH_TOKEN: ${{ github.token }}` is set on that step only (`:47`), checkout has `persist-credentials: false` (`:29`), and permissions stay `contents: write` (`:15-16`). (The old upload step read the output of a step id that did not exist and failed on all 8 runs, leaving releases backup-6/7/8 without the archive; those releases were left as they are.) `arcium-ci.yml:49-51` installs `cargo-audit --version 0.22.2 --locked` and prints its version before `cargo audit --file Cargo.lock`. **Enforcement:** the `action-pins` job (`arcium-ci.yml:21-28`; Arcium CI has no path filter) runs `.github/scripts/check_action_pins.py --self-test` and then the check, which scans every workflow and local action by glob, accepts only existing local paths, full lowercase SHAs with a version comment, or `docker://…@sha256:` digests, and fails on any `uses:` line it cannot parse. **Verified:** the check at `fbf7243`: `9 files: 30 pinned external, 5 local, 0 docker; 0 errors`, self-test 0 failed. Temporary controls (not committed): a SHA replaced by `@v4`, `@main`, a new workflow with an unpinned action, `docker://alpine:3`, a 39-character SHA, an unpinned reusable workflow and an unpinned composite-action step are all caught; a local action and a docker digest pass. CI: 12 runs on `596160a` (attempt 1) and the 5 push runs on the merge commit (Arcium CI 37250766339, Android CI 37250766366, Native Bridge 37250766348, Instrumentation 37250766374, two-device 37250766363) all `success`; the core-rust log prints `cargo-audit-audit 0.22.2`. **Not verified:** MONTHLY BACKUP REAL RELEASE TEST: NOT PERFORMED; MONTHLY BACKUP GITHUB WRITE PATH: NOT_VERIFIED. The draft/upload/verify/publish sequence is source-verified and was exercised against a stubbed `gh` (upload, asset-check and publish failures never published; a missing or empty ZIP failed before any `gh` call), but no real GitHub Release was created. This does not keep F-5 open: F-5 is the action and install supply-chain finding, and that condition is closed. **Scope:** a commit SHA stops an upstream tag or branch from being moved to different code. It does not protect against malicious code already in a pinned commit, a compromise of GitHub or the hosted runner, or of a registry used at run time (crates.io, npm, sdkmanager, rustup, the advisory database), and builds are not claimed to be bit-for-bit reproducible. The Rust toolchain (`stable`), the npm/Gradle graphs and the Android SDK/NDK packages are not pinned by this. |
| **F-6** | MED | `hybrid_encaps` panics on a malformed peer public key (future FFI DoS) | **FIXED** | Commit `3dcd9c81` (PR #52). `crates/core-crypto/src/hybrid.rs:78` returns `Result<_, HybridError>`; the former `.expect()` calls on peer input are `.map_err(\|_\| HybridError)?` (`:85-90`). Tests `encaps_rejects_wrong_length_ml_kem_key`, `encaps_rejects_empty_ml_kem_key`, `encaps_rejects_right_length_but_invalid_ml_kem_key` pass. (The return type now carries a `Zeroizing<[u8; 64]>`, A-3.) |
| **F-7** | LOW | The hybrid KEM combiner does not bind ciphertexts and public keys into the KDF | **FIXED** (dormant) | PR #56 (merge `88243800`). `combine_secrets` (`hybrid.rs:158-188`) binds `eph_pk`, `ml_ct` and the recipient's X25519 and ML-KEM public keys; test `real_encaps_binds_recipient_identity_not_just_shared_secrets` passes. **Caveat:** `hybrid_encaps`/`hybrid_decaps` have no callers outside `core-crypto` (a search of `crates/` finds none) and are not exported through UniFFI, so the binding is correct at code level and has no effect until the module is wired into session establishment. |
| **F-8** | LOW | Transient secret copies are not zeroized | **PARTIAL** *(corrected 2026-09-29)* | **Fixed:** the transients of the 2026-07 sweep (identity blob in `load_identity`, `derive_root`'s `ikm`, hybrid seeds, `ArciumCore::new`'s master-key `Vec`; PR #54 and `d68ab02`) and, in A-3 (PR #103), the secrets that `core-crypto` owns in the ratchet, KDFs, X3DH, hybrid and checkpoint paths and the FFI temporaries in `mobile-ffi` — see A-3 for what is wiped and where. **Before A-3.5, residual outside this crate's control:** secret-derived state inside `hmac 0.12.1`, `hkdf 0.12.4` and `sha2 0.10.9` values was not wiped by those crates — none of them depends on `zeroize` or implements `Drop`; a keyed `Hmac` keeps `K ⊕ ipad` and `K ⊕ opad` compression states and its output block, `Hkdf` keeps a PRK-keyed HMAC core, and their stack locals are not wiped either (`hmac-0.12.1/src/optim.rs:152-173, 207-219`, `hkdf-0.12.4/src/lib.rs:150-170, 228-262`, `sha2-0.10.9/src/core_api.rs:60-68`). A-3.5 enables partial upstream cleanup with `hmac 0.13.0` and `sha2 0.11.0`'s `zeroize` features; `hkdf 0.13.0` benefits transitively and has no `zeroize` feature of its own. The audited stock versions still leave local residuals, and complete safe-Rust source-level remediation has not been established or proven impossible; see H-9. (As of A-3.5, merged in PR #110 (`f72043e`), Arcium's own call sites use the 0.13/0.11 lines; see H-9 for what is and is not wiped.) Other transients still not wiped are H-2, H-6 and H-7 (H-1, H-3, H-4 and H-5 were closed by A-3.1, merged in PR #105). |
| **F-9** | LOW | `load_identity` panics on a poisoned mutex; masks wrong-key decryption as "no identity" | **FIXED — merged (PR #120)**, scoped to the store's own master key *(updated 2026-10-06; was PARTIAL)* | Evidence at `main` @ `e0e825c` (merge commit `e0e825c858d017f5158229a8df9d0ff81ae14dd9`, parents `28406b8` and PR HEAD `6fdb90d`; the merge tree equals the PR HEAD tree). **Both conditions of the review's definition are closed for `load_identity`:** (1) a poisoned mutex returns `Err(CoreError::Storage)` instead of panicking or returning `None` (`crates/mobile-ffi/src/lib.rs:664-671`); (2) errors are no longer collapsed into "no identity": `load_identity` returns `Result<Option<Arc<Identity>>, CoreError>` (`:664`), and its classifier `identity_from_record` (`:241-265`) maps only `StorageError::NotFound` to `Ok(None)` (`:244`). `Decryption` and a record that is not 64 bytes are the new `IdentityUnreadable` (`:151`, `:245-256`); every other storage error is `Storage` (`:250`). The error text names only the cause and, for a wrong length, the length; it carries no record content. **The overwrite the review described is closed on this path:** `save_identity` (`:638-654`) is create-only. One `store.transaction()` (`BEGIN IMMEDIATE`, `crates/core-storage/src/lib.rs:224-228`) reads the record and writes only on `NotFound` (`mobile-ffi/src/lib.rs:647-652`). A readable record is the new `IdentityAlreadyExists` (`:156`, `:649`); an unreadable record or any read error aborts, and nothing is written. `require_identity` propagates load errors and keeps `InvalidKey("no identity saved …")` for absence only (`:1030-1033`). **Android:** `IdentityState` is Loading, Present, Absent or Failed (`android/app/src/main/kotlin/com/arcium/messenger/data/IdentityRepository.kt:8-17`); a `CoreException` becomes `Failed`, never `Absent` (`:31-35`). `startDestinationFor` gives Loading and Failed no start destination and sends only Absent to onboarding (`ui/navigation/IdentityGate.kt:56-60`); the gate's retry only calls `load()` again (`:43-47`). Onboarding's `createOrLoadExisting` loads the stored identity on `IdentityAlreadyExists` and proceeds only once it has loaded (`data/IdentityRepository.kt:44-48`, `ui/onboarding/OnboardingViewModel.kt:33`). `MessengerService` catches the load error, reports `IdentityUnavailable` and keeps its loop running without creating anything (`messaging/MessengerService.kt:136`, `:150-156`). The bridge's generated-string inventory classifies the new `CoreException.IdentityUnreadable.msg` as `F`, Rust error text (`.github/actions/uniffi-android-bridge/generated-string-fields.txt:20`). **Verified (RUNTIME_VERIFIED) on `e0e825c`:** Arcium CI run 37415175397 (push, attempt 1, success). Its `core-rust` job runs `cargo test --workspace --locked`, which includes the ten tests in `crates/mobile-ffi/src/tests/identity.rs`: absence; a store locked by another connection; a poisoned mutex; corrupt ciphertext; record lengths 0, 1, 32, 63, 65 and 128; creation in an empty store; creation over a readable record; 10 rounds of racing creators; a failed creation. The failure and conflict tests compare the raw stored rows before and after. The per-test lines of that log were not read. Android Instrumentation run 37415175416 (push, attempt 1, success, `tests=23 failures=0`) names the six new tests: `IdentityInstrumentationTest.anEmptyStoreHasNoIdentity`, `aStoreThatCannotBeReadIsAnErrorAndRecoversUnchanged` and `aStoredIdentityIsNeverReplacedAndIsLoadedInstead` (native path; a read failure is injected by overwriting the database header), and `IdentityGateInstrumentationTest.aFailedReadShowsARetryAndNeverOnboarding`, `aRetryRecoversFromATransientFailure` and `onlyAStoreWithNoIdentityStartsOnboarding`. Android CI 37415175378, Native Bridge 37415175451 and two-device 37415175490: push, attempt 1, success. Records in the existing 64-byte format still load: `a_record_written_in_the_existing_format_loads_with_the_same_keys`, and the `legacy_upgrade` fixtures written by an older build. **Executor-reported only:** the mutation controls and disposable experiments of PR #120 were not reproduced for this row. These include a COMMIT refused before its commit point, after which nothing was stored and a retry stored the identity it returned. **Not verified:** the JVM `IdentityRepositoryTest` belongs to Android CI's `testDebugUnitTest` step, which succeeded, but no per-class result is available, so its execution is NOT_VERIFIED. A COMMIT that takes effect but reports an error has no fault injection; by source, a retry gets `IdentityAlreadyExists` and onboarding loads the stored identity (INFERRED). Physical devices and power loss are not covered. **Scope — read before citing:** FIXED covers load errors and identity creation under the master key the store was opened with. Record names are derived from the master key (`key_name_hash`, `storage_key`, `crates/core-storage/src/lib.rs:318`, `:330`; see F-10). Under a wrong, lost or replaced master key the lookup misses, and `load_identity` returns `Ok(None)`, which cannot be told apart from a first run. The app then onboards and creates a new identity in a separate row; the old row stays on disk, unreadable under that key, and peers see a new identity. `MasterKeyProvider` still creates a new master key when its blob is missing (`android/app/src/main/kotlin/com/arcium/messenger/security/MasterKeyProvider.kt:42-58`); PR #120 does not change this. This master-key-lifecycle path is **unresolved** and is not claimed here. Also unchanged: there is no reset or recovery flow for an unreadable identity, so onboarding stays blocked with an error and a retry. Overlapping retry loads can publish a stale gate state, and cancellation and double-tap handling are recorded observations, not fixed (INFERRED; none of them creates or replaces an identity). **Cross-ref (2026-11-06, `7455da8`):** the master-key path above is re-confirmed at `7455da8` (D-007 in "Reconciliation 2026-11-06"): a missing blob, a corrupted blob and a wrong key are now told apart there, and a Rust-level probe shows a new key on an existing database reads as `Ok(None)`, lets a second identity be saved, and leaves the original row readable under the old key. Status unchanged. **Update (2026-11-06, `090bb17`):** the start-up half of the master-key-lifecycle path above is closed by PR #133. On Android, an existing store with a missing, corrupted or unusable `master_key.blob` now blocks start-up on an error screen; no replacement key, onboarding or second identity follows, and the blob and store are left unchanged (see "Update 2026-11-06: master-key loss at start-up" for evidence and limits). The Rust-level behaviour described here is unchanged: a different key that reaches `ArciumCore` still reads as `Ok(None)`. F-9's status is unchanged. |
| **F-10** | LOW | Storage: plaintext key names, size/pattern metadata leak, no rollback or secure-delete | **FIXED** *(scope stated 2026-09-29)* | PR #58 (merge `b2d3c5db`). **Covered:** (a) key names — `kv.k` is a `BLOB` of two HKDF-derived hashes and the name itself is stored encrypted in `ek` (`crates/core-storage/src/lib.rs:103-107`, `key_name_hash` `:286`, `storage_key` `:298`, `encrypt_key_name` `:320`); (b) `PRAGMA secure_delete = ON` (`:102`). Tests `key_names_are_not_stored_in_plaintext` (`:709`), `secure_delete_pragma_is_enabled` (`:775`), `deleted_row_bytes_are_overwritten_on_disk` (`:787`) pass. **Not covered, and not claimed:** row count and ciphertext length (no padding); rollback protection — an older copy of the database file is accepted (module doc `:15-21`; `docs/S2-B2-DURABLE-MESSAGING.md` §8, "malicious rollback … not provided"); `VACUUM`/`auto_vacuum`. The review itself called padding and rollback counters optional. FIXED here means the two sub-issues the review's fix named, not that the store is metadata-private against someone holding the file. **Cross-ref (2026-11-06, `7455da8`):** besides the whole-file case, a single record can be rolled back by writing its older ciphertext into its own row; this is accepted, while moving a ciphertext into another record's row is refused (D-009 in "Reconciliation 2026-11-06", RUNTIME_VERIFIED by temporary probes). Status unchanged. |
| **F-11** | LOW | CI integrity: `arcium test` failure swallowed; dead `CLAUDE_SUCCESS`; Pi reviews a truncated diff | **FIXED** *(corrected 2026-09-29)* | `.github/workflows/arcium-ci.yml`: `arcium build` and its verification steps are plain commands that fail the job (`:53-54`, `:67-90`); the borsh tests run under `set -o pipefail` with a required-tests-ran check (`:81-90`); `arcium test` runs under `set -o pipefail` and `tee`, and fails on no passing test or any pending test (`:114-128`). The other two sub-items belonged to workflows that were deleted (`17682c5`, see F-5). The `\|\| true` that remain are diagnostics and gate nothing: tool versions (`:62-66`) and an `if: failure()` log dump (`:129-136`). CI evidence on `087b9c8`: Arcium CI run 36488538945, `arcium-build` and `arcium-test` `success`, `arcium-test` log `6 passing`. |
| **F-12** | LOW | Kotlin crypto stubs return plaintext as "ciphertext" | **FIXED** *(corrected 2026-09-29)* | `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt` no longer contains `ratchetEncrypt`, `ratchetDecrypt` or `x3dhInit` (a search of `android/app/src/main` finds none). Messaging methods forward to the generated UniFFI calls (`:63-250`); `submitPsiQuery` (`:257-263`) and `startTorTransport` (`:270-276`) throw `NotImplementedError` instead of returning a value that could be mistaken for a result. This is a static read; no Android tooling was used for this row (the Android CI jobs exercise the wrapper, but their results are not cited here). *(Note 2026-11-28: `startTorTransport` was removed by PR #276; `submitPsiQuery` still throws; see "Update 2026-11-28: Tor route in Settings and core fixes". Status unchanged.)* |
| **F-13** | INFO | X3DH: SPK signature lacks domain separation; OPK single-use unenforced | **FIXED** *(corrected 2026-09-29)* | (a) Domain separation: see F-2 (`x3dh.rs:17`, `:69-82`); a raw-key signature does not verify (test `signatures_from_other_contexts_are_rejected`). (b) One-time-prekey single use: `accept_first_message` (`mobile-ffi/src/lib.rs:849-927`) takes the one-time prekey (`:879`), rotates the prekey record (`:880-883`) and replaces it through a conditional `SideWrite::replace` (`:905-911`) in the same transaction that promotes the session; a lost race is `OneTimePrekeyUnavailable` (`:922`); `check_answerable` (`:824-838`) refuses a wrong id or a stripped one-time prekey. Tests `matching_one_time_prekey_is_consumed_and_replaced`, `replaying_an_accepted_handshake_is_rejected_and_changes_nothing`, `concurrent_first_messages_create_one_session_and_consume_the_prekey_once`, `stripping_the_one_time_prekey_is_refused_rather_than_downgraded`, `wrong_one_time_prekey_id_does_not_consume_the_current_one` pass. **Scope:** single use is enforced only where the responder holds a one-time prekey; a handshake answered without one has no replay property (`mobile-ffi/src/lib.rs:769-772`). |
| **F-14** | INFO | On-chain placeholders and result-delivery gap (pre-deploy) | **NOT-FIXED (pre-deploy)** · behavior `NEEDS-HOME` | `arcium-psi/programs/arcium-psi/src/lib.rs:7` — placeholder `declare_id!("PSiArc1um111…")`. The callback verifies the output signature (`:133-136`) but only `msg!`-logs the client's encryption key (`:141-144`); the match vector is written to no account or event. Legacy `submit_query` (`:21-32`) still ignores `encrypted_contacts` (`:30`). Access control on the implemented instructions read sound statically (payer-seeded `init_user` PDA `:153-158`, `has_one = owner` `:167`, monotonic nonce `:27`); MXE authority semantics are `NEEDS-HOME`. |
| **F-15** | INFO | Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir` | **NOT-FIXED (design)** · `NEEDS-HOME` *(scope clarified 2026-09-29)* | (a) `android/app/src/main/kotlin/com/arcium/messenger/network/SolanaClient.kt:7` uses `BuildConfig.SOLANA_RPC_URL` directly (clearnet). (b) `crates/core-transport/src/lib.rs:23-24` — `new(_state_dir)` ignores its argument and uses `TorClientConfig::default()`. **Scope:** the review wrote "messaging rides Tor (arti)"; that is not true of current code. `core-transport` is a `mobile-ffi` dependency in `Cargo.toml` but no source in `crates/` calls it, and `docs/NET-MESSAGING.md` records Tor as a stub and future work (`:25`) and states the relay path has "no anonymity and no Tor" (`:138-139`, `:231`). So F-15 covers the unwired Tor transport and the PSI/Solana RPC path only; the relay path's lack of anonymity is a documented design limit, not something this row tracks or claims to fix. **Cross-ref (2026-11-06, `7455da8`):** `TorTransport::new` also has no bootstrap timeout and still has no production caller (D-008 in "Reconciliation 2026-11-06"). Status unchanged. *(Note 2026-11-20: `core-transport` is no longer a `mobile-ffi` dependency (PR #232); see "Update 2026-11-20: core-transport not a mobile-ffi dependency". Status unchanged.)* *(Note 2026-11-24: arti is 0.48 since PR #262; (b) is unchanged; see "Update 2026-11-24: arti 0.48 in core-transport". Status unchanged.)* *(Note 2026-11-24: (b) is fixed by PR #265; see "Update 2026-11-24: Tor connector in core-transport".)* *(Note 2026-11-27: the Tor transport now has a caller in the app's core, for a relay at an onion address only (PR #275); see "Update 2026-11-27: Tor for onion relays". Status unchanged.)* *(Note 2026-11-28: Settings labels whether the relay is reached through Tor, by a Kotlin copy of the core's rule, and the Kotlin Tor stub is gone (PR #276); see "Update 2026-11-28: Tor route in Settings and core fixes". Status unchanged.)* |
| **F-16** | INFO | TS client: raw ECDH output used directly as the `RescueCipher` key | **VERIFIED-BENIGN** at `@arcium-hq/client` 0.10.4 *(resolved 2026-09-29)* | The 2026-07 row was `CANNOT-VERIFY-FROM-CODE` because the library's derivation was not read. It can be read: `RescueCipher`'s constructor derives the key with `RescuePrimeHash` over `counter ‖ sharedSecret ‖ L`, a single-step KDF after NIST SP 800-56C Option 1 (`@arcium-hq/client@0.10.4`, `src/cryptography/rescueCipher.ts:13-20` and `rescueCipherCommon.ts:38-75`; source obtained with `npm pack` of the pinned version). `arcium-psi/tests/src/client.ts:16` still returns the raw X25519 output and `:28`, `:47` pass it to `new RescueCipher(...)`, so the raw point is not itself the cipher key. **Limits:** verified for 0.10.4 only — `package.json:10` allows `^0.10.4` and the lockfile pins 0.10.4; the review's other two notes stand unchanged — no contributory-behavior (low-order point) check exists in this repository's code, and nonces are caller-supplied (`client.ts:19-23`, `:36-40`), so a production caller must guarantee per-query uniqueness (the tests reuse fixed nonces). This client lives under `arcium-psi/tests/`. |
| **F-17** | INFO | `CLAUDE.md` carries derived-from-source content that drifts and is loaded as authoritative every session | **FIXED** | **Closed by inspection at `main` @ `1a7b1904`** — `CLAUDE.md` (blob `4a860dd3`, 171 lines) read in full against the closure condition below: no file/workflow counts, no directory trees, no listings of function signatures or APIs, and — applying the condition's general term rather than only its three named examples — no status tables, branch lists, or PR history either. The file additionally now carries a standing rule against re-introducing such content («Правила работы» → «Не инвентаризируй состояние репозитория»), so the state is asserted as a rule and not only as an absence. The edits landed in PRs #60, #62, #64, #65, #66, all merged before this tracker update per the fix-first rule; this row's PR changes no code and does not touch `CLAUDE.md`. Verification basis, how independent the check was, the four borderline cases weighed, and the scope limit of this closure: see [F-17 closure record](#f-17-closure-record) below. **Original defect and closure condition, retained verbatim:** The defect is not that specific counts are stale — it's that `CLAUDE.md` holds content *derived from* the repo (workflow tables, repo-structure trees, API signature listings) with nothing that re-derives it when the source changes, and this file is read into every session as ground truth. Concrete case, already in this repo's history: before PR #60, `CLAUDE.md`'s "Ключевые API" section documented `hybrid_encaps` as returning a plain tuple; `crates/core-crypto/src/hybrid.rs` had by then returned `Result<(Vec<u8>, [u8; 64]), HybridError>` since F-6 (PR #52). A session loading that section would write code against a signature roughly 8 PRs out of date, with no signal that it had drifted short of reading the source directly — sharper than a workflow-count mismatch, since it teaches a wrong API rather than an outdated inventory. PR #60 resolved that one instance by deleting the section rather than re-deriving it; the same class of content (repo-structure map, workflow table) is still present elsewhere in the file. **Closure condition, checkable by inspection and independent of any specific number:** `CLAUDE.md` contains no inventories of repository state — no file/workflow counts, no directory trees, no listings of function signatures or APIs. A single version constraint recorded as a warning is not an inventory. |

### F-17 closure record

**What was checked.** `CLAUDE.md` at `main` @ `1a7b1904` (blob `4a860dd3`, 171 lines) was
read in full against the closure condition quoted in the F-17 row, applying that
condition's general term — "inventories of repository state" — with its three named
categories treated as examples rather than an exhaustive checklist. That is the reading
recorded in PR #66, and it is what the condition's own carve-out requires: a single
version constraint would never have matched "file/workflow counts", "directory trees",
or "listings of function signatures or APIs" in the first place, so under a narrow
three-category reading the carve-out would exclude nothing.

**How independent the check was.** The checking pass was given the condition text and its
reading, was barred from opening the diffs of the PRs that edited `CLAUDE.md` (#60, #62,
#64, #65, #66), and did not reconstruct the removed content by any other route — the
verdict was reached from the file's current text alone. Its independence was partial, not
total: the same session had, earlier in the same run, read the post-merge `CLAUDE.md` and
the body of PR #66, and it disclosed this before starting. A genuinely cold pass — a
session handed only `CLAUDE.md` and the condition — would be stronger evidence than what
backs this row. Recorded rather than smoothed over, so a later reader can weigh the
evidence and not just the verdict.

**Borderline cases weighed and found not to be inventories.** Written down so a later pass
can see they were considered rather than missed:

- *The «Версии» block (four dependency pins).* Against: derived from the manifests, and it
  drifts whenever a version is bumped. For: each line is a constraint recorded with its
  reason ("требует anchor-lang =1.0.2", "не 0.2", "не менять без причины") — the
  compatibility decision is not re-derivable from the manifest, which records what is
  pinned but never why it may not move. The carve-out covers exactly this shape; its
  singular ("a single version constraint") reads as a description of the form of one
  entry, not a quota of one per file.
- *«Сейчас STUB на chacha20poly1305» for `crates/core-crypto/src/rescue.rs`.* Against: a
  statement about current source that goes stale the moment the stub is replaced. For: it
  is written as a prohibition with its rationale ("НЕ заменяй … пока circuit не
  задеплоен"; arcium-client would pull the whole Solana/Anchor stack into the Android
  `.so`) — a NO-GO decision, the same shape the carve-out protects, not a listing.
- *Single pointer facts — "TS-сторона уже следует этому (tests/src/utils.ts)" and
  "Kotlin-биндинги уже скомпилированы в …/ffi/ArciumCore.kt".* Against: one-off assertions
  about the current state of named files, and they will drift silently. For: a lone fact
  attached to a canonical rule is neither a count, a tree, nor a signature listing, and
  the carve-out concedes that not every recorded fact is an inventory. These sit closest
  to the line of anything left in the file.
- *The «Открытые задачи» block.* Against: status-shaped, it drifts as items close, and
  "PR #5 … ✅ смёржен 2026-06-07" is repository history rather than an open task — the
  strongest single argument for a stricter verdict. For: the block enumerates what is
  absent and owed (no billed API key, no devnet deploy, branch protection not enabled),
  which is not derived from source at all and cannot be re-derived by reading it; each
  entry is a warning or a REVISIT condition, not a count, tree, or signature listing.

**Scope of this closure — read this before citing it.** The closure condition is narrower
than the defect described in the F-17 row. FIXED here means the class of content the
condition names is gone from `CLAUDE.md`. It does not mean `CLAUDE.md` is structurally
protected against drift. Single derived facts remain in the file — the pointers and the
version pins listed above — and they do not violate the condition. The standing rule added
to «Правила работы» is a rule, not a mechanism: nothing re-derives or re-checks the file
when the source changes. If what is wanted is drift-immunity rather than
inventory-removal, that is a different problem, it is not covered by closing F-17, and it
would need its own finding.

**Re-check at `main` @ `087b9c8` (2026-09-29).** The closure above records what was checked
at `1a7b1904`; it is not re-derived. What was re-read on `087b9c8`: `CLAUDE.md` (186 lines)
still carries the standing rule against inventories, now in section «Что за проект»
(`CLAUDE.md:22-28`; the «Правила работы» heading the record names no longer exists), and a
reading of the file finds no file or workflow counts, directory trees, or function-signature
listings. Differences from the record: the «Открытые задачи» block it weighed is gone; the
«Версии» block (`:145`) and the RescueCipher-stub note (section «КРИТИЧЕСКИЕ криптографические правила», `:31`) remain and are still
prohibition-shaped; the «Навыки» list (`:170`) names the skills under `.claude/skills/` and
is the closest thing to an inventory now in the file — it drifts if a skill is added or
removed, and it is recorded here as borderline rather than as a violation. The two cautions
above still apply: the closure covers the class of content the condition names, not
drift-immunity, and this re-check speaks only for this commit.

---

## A-series (opened after the 2026-06 review)

Each row was re-derived from `main` @ `087b9c8`. The pull request numbers are where the
change landed; the evidence column is what this snapshot re-read.

| ID | Description | Status | Evidence (`main` @ `087b9c8`) |
|----|-------------|--------|-------------------------------|
| **A-1** | A received X3DH handshake used to create a responder session at once, so an unauthenticated (public) handshake held the peer's slot and later handshakes from that peer were refused. Also: sessions already stored in that shape by older builds. | **FIXED** (PR #101 and its legacy-upgrade part) | Receiving a handshake now creates no session: `establish_session_responder` (`crates/mobile-ffi/src/lib.rs:738-805`) records only a *provisional* `hsin:v1/<handle>` record (key `crates/core-protocol/src/messaging/records.rs:31-33`; `Messenger::record_provisional_handshake` `crates/core-protocol/src/messaging.rs:197`). The session is created by `accept_first_message` (`messaging.rs:276`, FFI `mobile-ffi/src/lib.rs:849-927`) only when the initiator's first message authenticates under the keys the handshake derives; a failed authentication writes nothing (`messaging.rs:262-265`). Legacy upgrade: a stored responder session of exactly the old untouched shape is retired, in one transaction, when a later handshake from the same peer is recorded (`crates/core-protocol/src/messaging/legacy.rs:1-21`, `is_legacy_unconfirmed` `:42`, `retire_legacy` `:74`); one that authenticated anything, sent anything, or differs in shape is never retired. Tests (in the passing suites of CI run 36488538945): `only_the_untouched_old_responder_shape_is_legacy_unconfirmed` (`messaging/tests/legacy.rs:146`), `every_other_shape_keeps_its_session_and_changes_nothing` (`:172`), `a_legacy_session_is_retired_into_the_new_handshake_and_nothing_else_changes` (`:265`), `encrypt_or_decrypt_before_handshake_creates_no_ownership` (`mobile-ffi/src/lib.rs:1541`). **Scope:** this closes "a handshake alone creates a session". By design a later handshake for the same handle still replaces the provisional record (`mobile-ffi/src/lib.rs:742-743`), and no property is claimed about who the sender is beyond what the first message's authentication proves. The prekey record and the one-time prekey a retired legacy session consumed are not restored (`legacy.rs:19-21`). |
| **A-2** | The relay's mailbox read (`FETCH`) returned the first N envelopes only, so a retained prefix (envelopes the client keeps for later, or junk sent to the mailbox) could hide later envelopes, including a handshake or a message that follows it. | **FIXED** (PR #102) | Relay op 6 `FETCH_AFTER recipient after max` (`crates/relay/src/protocol.rs:15-28`, server `crates/relay/src/server.rs:195, 307`, client `crates/relay/src/client.rs:99`) pages forward from a sequence number. The client runs a two-pass scan — `Pass::Handshakes`, then `Pass::Messages` (`crates/mobile-ffi/src/network.rs:127-132`, `scan` `:365`) — paging with `fetch_after` (`:377`), bounded by `MAX_SCAN_PAGES` and `MAX_SCAN_ENVELOPES = DEFAULT_MAX_MAILBOX` (`:118-125`), rejecting a relay that returns out-of-order sequence numbers (`:391-395`). Tests: `fetch_after_pages_through_a_mailbox_without_removing_anything` (`crates/relay/src/lib.rs:107`), `a_relay_without_fetch_after_refuses_it_explicitly` (`:262`), `a_retained_prefix_of_any_length_no_longer_hides_a_later_message` (`crates/mobile-ffi/src/tests/mailbox_scan.rs:177`), `a_handshake_behind_a_retained_prefix_still_opens_its_session` (`:310`). **Scope:** the relay is untrusted and remains able to withhold envelopes; the scan is bounded, and the code says a relay can keep the rest out of one round's reach (`network.rs:118-119`). A relay that predates op 6 answers `BAD_REQUEST` and the client has no fallback (`protocol.rs:36-38`). Sequence numbers are transport positions only, not evidence of anything (`protocol.rs:30-33`). |
| **A-3** | Secret key material outlived its use: `Copy` key types and by-value copies in the ratchet, KDF, X3DH, hybrid, checkpoint-decode and FFI paths. | **PARTIAL** (PR #103) | **Done:** the ratchet's secret fields and every key-derived temporary that `core-crypto` owns are `Zeroizing`/wiping types (`crates/core-crypto/src/ratchet.rs:50-52`; `impl ZeroizeOnDrop for DoubleRatchet` `:350`; no manual `Drop` on the ratchet); the rollback snapshot wipes through its fields; X3DH (`x3dh.rs:106, 151`), hybrid and checkpoint decode hold their secrets in `Zeroizing`; the FFI temporaries in `mobile-ffi` are wrapped (`mobile-ffi/src/lib.rs:336-337, 364-376, 570, 582, 600, 606-607`). Wire and checkpoint formats are unchanged. Tests: compile-time pins `secret_fields_are_wiping_types` (`ratchet.rs:832`), drop-time probes `secret_fields_wipe_on_drop` (`:862`) and `the_production_container_wipes_on_drop` (`:904`), `no_temporary_key_outlives_an_operation` (`:983`), `copies_and_restores_give_every_key_back` (`:1040`). **Not done — why it is PARTIAL:** secret-derived state inside third-party `hmac`/`hkdf`/`sha2` values (H-9) and the items H-2, H-6…H-8, H-10 (H-1, H-3, H-4, H-5: see A-3.1). Not established: the actual memory contents after drop on a device, and that the Android release `.so` keeps `zeroize`'s writes (H-8); the wipe tests show *where* containers are dropped, not that memory was cleared. |
| **A-3.1** | Arcium-owned lifetime hardening of four leftovers of A-3 (ARCIUM-SECRET-LIFETIME-HARDENING-002): the X3DH initiator session's `Debug`, `core-storage` subkeys, the master-key copy in `ArciumCore::new`, and staged plaintext. A-3 itself stays PARTIAL (H-9 and others below). | **FIXED — merged** in PR #105 (merge commit `6266c0befedefb0523d4fc354d6f7db6ad206c29`) — verified at code commit `bb6b633` (a later commit in the PR changed only this file) | H-1: `crates/core-storage/src/lib.rs:330, 367` return `Zeroizing<[u8; 32]>`, the master key is `Zeroizing` (`:62`) and there is no manual `zeroize()` left in the file. H-3: manual `Debug` for `AliceSession` (`crates/core-crypto/src/x3dh.rs:114`) prints `<redacted>` for `root_key`. H-4: `ArciumCore::new` borrows the key (`crates/mobile-ffi/src/lib.rs:576`, `EncryptedStore::open_with_key` `core-storage/src/lib.rs:75`), and the store makes the one copy it keeps, in its wiping owner (`:286`). H-5: `stage_decrypt`, `stage_first_decrypt` and `promote_with` carry `Zeroizing<Vec<u8>>` (`crates/core-protocol/src/durable.rs:727, 906, 921`), so a staged transition that is dropped, rejected, unresolved or conflicted wipes the plaintext, while a successful commit moves it to the caller unwiped. Tests: `alice_session_debug_does_not_print_the_root_key` (`x3dh.rs:492`), `a_handshake_sessions_debug_does_not_print_its_derived_root_key` (`:516`); `master_key_and_subkeys_are_wiping_types` (`core-storage/src/lib.rs:604`), `subkey_derivations_match_independent_hkdf` (`:615`), `every_error_exit_after_a_subkey_derivation_is_reached` (`:636`), `open_with_key_and_open_are_interchangeable` (`:686`); `core_new_checks_key_length_and_opens_the_same_store` (`mobile-ffi/src/lib.rs:1075`); `staged_plaintext_is_held_in_a_wiping_type` (`durable.rs:1791`), `a_successful_commit_hands_the_output_to_the_caller_undestroyed` (`:1849`), `an_abandoned_transition_drops_its_output_and_changes_nothing` (`:1870`), `every_failed_commit_drops_the_staged_output` (`:1889`), `a_first_message_is_released_only_by_a_successful_promotion` (`:2010`). **Limits:** the wiping is by ownership (`Zeroizing`, drop glue); no test reads freed memory, and the `Debug` test covers accidental formatting only. Not covered: `by-value` arguments (`EncryptedStore::open` still takes `[u8; 32]`, used by tests only), stack copies of moved values, `hmac`/`hkdf`/`sha2` state (H-9), the `IndexMap` remnants (H-6), the raw `DoubleRatchet::decrypt` return value before the durable layer wraps it, and other types that derive `Debug` over plaintext (see H-11). The regression that reintroduces an ordinary key array inside `ArciumCore::new` is **not** caught by any test. |
| **A-3.2** | Plaintext-lifetime and Debug hardening of the messaging receive path (ARCIUM-PLAINTEXT-LIFETIME-HARDENING-003): decrypted message text reached `Debug` output through several plaintext-bearing types (H-11), and the raw `DoubleRatchet::decrypt` returned the plaintext as an ordinary `Vec<u8>` (H-12). A-3 itself stays PARTIAL (H-9 and others below); A-3.1 is unchanged by this stage. | **FIXED — merged** in PR #106 (merge commit `e5331edf70ba19ab334e447b2edeecdd48b62d0b`) — verified at code commit `460c6e2` (later commits in the PR changed only this file or a test comment, no non-test code) | H-12: `DoubleRatchet::decrypt` returns `zeroize::Zeroizing<Vec<u8>>` (`crates/core-crypto/src/ratchet.rs:210`); the AEAD's buffer is wrapped at its single source, `aead_decrypt` (`:435`), so the in-order, skipped-key and DH-ratchet paths all return the wiping owner; `stage_decrypt` (`crates/core-protocol/src/durable.rs:728`) passes it through and the staged transition moves it to the caller unwiped, as before. The AEAD checks the tag before it applies the keystream (`chacha20poly1305-0.10.1/src/cipher.rs`, `decrypt_in_place_detached`), so a failed decrypt never holds plaintext. H-11: manual `Debug` that prints ids and metadata and `"<redacted>"` for the text, replacing derived `Debug`, on `core_protocol::messaging::IncomingMessage` (`messaging/types.rs:58`), the FFI `IncomingMessage` (`crates/mobile-ffi/src/messaging_api.rs:118`), `ReceivedText` (`network.rs:71`), `Payload` (`network/wire.rs:98`) and `ChatEntry` (`network/chat.rs:112`; not in the original H-11 list, found by this stage's search); `Received`, `ReceiveResult` and `Conversation` derive `Debug` over those and are covered through them. No production code formats any of these (no `println!`, `dbg!`, `log` or `tracing` use in the crates, two unrelated `{:?}` sites, and no `Log.*` call in `android/app/src/main`): this closes a type-level exposure, not an observed log leak. Network receive: `ArciumCore::receive_committed` and `pending_committed` (`messaging_api.rs:180, 212`, plain `impl`, not exported through UniFFI) return the messenger's own types; the exported `receive_message` and `pending_incoming` wrap them, so their behaviour is unchanged. The network layer and chat refresh use the internal ones (`network.rs:600, 649, 658`, `chat.rs:799`), so a text no longer passes through the application's plain `Vec<u8>` record between the messenger and the boundary. Tests: `decrypt_returns_a_wiping_owner_on_every_path` (`ratchet.rs:637`), `a_failed_decrypt_returns_no_plaintext` (`:683`), `the_released_plaintext_is_the_staged_buffer_not_a_copy` (`durable.rs:1854`), `a_committed_incoming_message_does_not_print_its_plaintext` (`messaging/tests.rs:654`), and in `mobile-ffi/src/tests/debug_redaction.rs`: `ffi_incoming_message_and_its_results_hide_the_plaintext` (`:56`), `received_text_hides_the_text` (`:78`), `payload_hides_a_text_and_shows_the_rest` (`:90`), `chat_entry_and_conversation_hide_the_text_and_keep_the_metadata` (`:109`), `what_a_real_receive_returns_hides_the_plaintext` (`:137`). **Limits:** the Debug hardening covers accidental formatting and logging only. The application's own copy of a text (`IncomingMessage.plaintext`, `ReceivedText.text`, `ChatEntry.text`) is a plain `Vec<u8>` or `String` by design of the UniFFI records and is outside Rust's wiping once it crosses the boundary; Kotlin-generated classes are not covered (H-14). A copy made between the ratchet and staging (for instance a `.to_vec()`) is **not** caught by any test: the heap-address test compares the staged and the released buffer, not the ratchet's. Not covered: the outgoing path (H-13), the `Payload::decode` copy that strips the type byte (wiping, retained), `hmac`/`hkdf`/`sha2` state (H-9). |
| **A-3.3** | Outgoing plaintext-lifetime hardening (ARCIUM-OUTGOING-PLAINTEXT-LIFETIME-HARDENING-004): the outgoing text left its wiping owner for an ordinary `Vec<u8>` on two production paths before `send_message` wrapped it again (H-13). A-3 itself stays PARTIAL (H-9 and others below); A-3.1 and A-3.2 are unchanged by this stage. | **FIXED — merged** in PR #107 (merge commit `a96d72b7a00ceb720fdb5360aec216350b69afa7`) — verified at code commit `8dd6912` (a later commit in the PR changed only this file) | `ArciumCore::send_committed` (`crates/mobile-ffi/src/messaging_api.rs:181`) and `NetworkMessenger::send_committed_text` (`crates/mobile-ffi/src/network.rs:277`) are internal (plain `impl` blocks, not exported through UniFFI) and take the plaintext in a wiping owner: the first borrows a `&Zeroizing<Vec<u8>>` and passes it to `Messenger::send`, the second takes the text's `Zeroizing<Vec<u8>>`, moves it into `Payload::Text`, and lends the wiping encoding (`:284`) to `send_committed`. The exported `send_message` (`messaging_api.rs:285`) and `send_text` (`network.rs:213`) wrap their argument first (`:291`, `:219`) and call them, so each keeps one implementation and its behaviour; `send_message` now wraps before its first fallible step. `refresh` moves a queued entry's own wiping text into `send_committed_text` (`network/chat.rs:829`). The two ordinary copies H-13 names, `Payload::Text(text).encode().to_vec()` and `e.text.to_vec()`, are gone, and no ordinary owner of the text replaced them in Arcium's code between the FFI entry and `Messenger::send`. Payload, wire, durable, idempotency and retry behaviour are unchanged; the bytes given to `Messenger::send` are the same. Tests: `the_internal_send_functions_take_a_wiping_owner` (`mobile-ffi/src/tests/outgoing.rs:22`, signature pins), `the_exported_and_the_internal_send_are_one_path` (`:31`), `a_sent_text_arrives_byte_for_byte` (`:97`; empty, ASCII, UTF-8, every byte value, 16 KiB), `a_queued_chat_text_is_sent_unchanged_once_a_session_exists` (`:130`), `payload_bytes_are_pinned_and_held_in_a_wiping_owner` (`network/wire.rs:228`); the byte tests also pass on the base commit `e5331ed`. **Limits:** a copy made inside a function that keeps these signatures (for instance an ordinary clone just before `Messenger::send`, or a return to the exported `send_message`/`send_text` with `.to_vec()`) is **not** caught by any test; catching it would need an allocation-counting allocator (`unsafe`). The AEAD's own staging buffer in `aead_encrypt` (`aead-0.5.2/src/lib.rs:385-395`) holds a plain copy that the keystream overwrites in place before it returns; it is dropped unwiped only on an error that needs a message of about 256 GiB. Not covered: the application's copies across the boundary (UniFFI lifting of `Vec<u8>`/`String`, `ChatEntry.text`), Kotlin-generated classes (H-14), `hmac`/`hkdf`/`sha2` state (H-9), stack copies, physical memory. |
| **A-3.4** | Generated-Kotlin plaintext stringification (ARCIUM-KOTLIN-PLAINTEXT-STRINGIFICATION-HARDENING-005): the UniFFI-generated Kotlin records that carry message plaintext printed it from `toString` and string templates (H-14). A-3 itself stays PARTIAL (H-9 and others below); A-3.1…A-3.3 are unchanged by this stage. | **FIXED — merged** in PR #108 (merge commit `5d61d5a740d3fd1ce4137020fae68c1a1bf37486`) — verified at code commit `a349966` (later commits in the PR changed only documentation) | **Observed before** (Kotlin generated from `main` @ `a96d72b` by `uniffi-bindgen` 0.28.3 through the bridge action's steps, compiled with Kotlin 2.0.21 and run on the JVM): the records are `data class`es, whose generated `toString` prints every property — `ChatEntry.text` (`String`) verbatim, `IncomingMessage.plaintext` and `ReceivedText.text` (`ByteArray`) as their decimal bytes (`Arrays.toString`); `ReceiveResult.Accepted`/`Duplicate`, `Conversation.last` and lists of these printed the same transitively. A bare `ByteArray.toString()` printed only `[B@…`. `OutgoingMessage.wire` is ciphertext. **Change:** the three fields use UniFFI custom types `PlaintextBytes`/`PlaintextText` (`crates/mobile-ffi/src/plaintext.rs:12, 16, 18-19`; fields `messaging_api.rs:114`, `network.rs:67`, `network/chat.rs:107`), mapped by `crates/mobile-ffi/uniffi.toml:6, 11` to Kotlin value classes of the same names whose `toString` is `"<redacted>"` (`android/app/src/main/kotlin/com/arcium/messenger/ffi/Plaintext.kt:17-24`); equality and hashing are the wrapped value's, and the application reads `.bytes`/`.value`. No generated file is edited or committed. UniFFI symbols (93) and all 44 generated method/constructor signatures are unchanged; the Kotlin types of those three fields change, and their call sites are updated. **Fail-closed:** the bridge action (`.github/actions/uniffi-android-bridge/action.yml:126`) runs `check_generated_plaintext.py`, which requires every generated constructor property of type `kotlin.String`, `kotlin.ByteArray` or `Plaintext*` to match `generated-string-fields.txt` exactly (28 fields, 3 of them message plaintext), the custom types to be imported rather than typealiased, and every property to be parsed; it then proves on mutated copies of the real file that it rejects a plaintext field back to a builtin type, typealiased custom types, a new unclassified `String` field and a changed class header. Tests: `GeneratedRecordStringificationTest` (JVM, generated classes built directly; `android/app/src/test/.../ffi/`), `PlaintextStringificationInstrumentationTest` (device, values a real send and receive return; `android/app/src/androidTest/.../ffi/`) — the canary appears in no textual, decimal, `contentToString` or hex form, and ids/state still do. **Limits:** covers accidental formatting of the generated records only; code that reads `.value`/`.bytes` and logs it, method parameters and return values (not formatted as records), Kotlin/Java strings and byte arrays in memory, and UI memory are not covered. No production `Log.*`, `Timber`, `println` or `System.out` call exists in `android/app/src/main` or `src/debug`, so no log leak was observed before either. |
| **A-3.5** | Upstream-supported partial hardening of third-party secret state (ARCIUM-H9-UPSTREAM-MEMORY-HARDENING-A3.5): `hmac 0.13.0` and `sha2 0.11.0` enable their `zeroize` features; `hkdf 0.13.0` has no `zeroize` feature of its own and benefits transitively through its HMAC context's feature-enabled SHA state and digest block buffer. The storage KDFs now hold and wipe the HKDF pseudorandom key. **Partial:** H-9 becomes PARTIALLY_FIXED, not FIXED. A-3 itself stays PARTIAL (H-9 residuals and others below); A-3.1…A-3.4 are unchanged by this stage. | **FIXED — merged** in PR #110 (merge commit `f72043e4c92ccee54e308709091139871bef6359`) — verified at code commit `1fe320c` (later commits in the PR, up to its final HEAD `cb71e9e`, changed only this file) | **Graph** (`cargo metadata` on the A-3.5 tested tree; at that time the root lockfile was untracked, see H-10 and A-3.7): `hmac 0.13.0` (feature `zeroize`), `hkdf 0.13.0` (no features), `sha2 0.11.0` (`zeroize`, `alloc`, `default`, `oid`) over `digest 0.11.3` (`zeroize`), `block-buffer 0.12.1` (`zeroize`), `crypto-common 0.2.2`, `hybrid-array 0.4.15`, `zeroize 1.9.0`; declared at `Cargo.toml:20-22`. At `31f7915` it was `hmac 0.12.1`, `hkdf 0.12.4`, `sha2 0.10.9`, `digest 0.10.7`, none with `zeroize`. Direct users: `core-crypto` (all three), `core-storage` (`hkdf`, `sha2`), `core-protocol` and `mobile-ffi` (`sha2`). **Arcium-owned change:** the HMAC key constructor moved to `KeyInit::new_from_slice`; `hmac_tag` (`crates/core-crypto/src/ratchet.rs:416-421`) borrows the `CtOutput` until it is copied into the wiping destination and does not call `into_bytes`, which takes `&self` in `digest 0.11` and would clone the tag (`digest-0.11.3/src/mac.rs:207-209`). Before A-3.5, this Arcium path already explicitly wiped the caller-owned output after copying it; the new path preserves that protection through `CtOutput`'s drop cleanup and avoids the ordinary clone the new API would make; the three storage KDFs take the HKDF pseudorandom key from `extract` and wipe it (`KeyMaterial::hkdf`, `crates/core-storage/src/lib.rs:298-302`) where `Hkdf::new` dropped it unwiped. The existing `extract` + wipe in `kdf_rk`, `derive_root` and `combine_secrets` is kept. No `unsafe`, no custom or copied crypto, no fork or patch. **Cleanup provided by the upgraded dependency graph** (drop cleanup in the resolved versions, sources read; new in A-3.5 are the owned `Sha256` state cleanup, the `BlockBuffer` cleanup and the cleanup of the bytes owned by `CtOutput` in the new API — together with the Arcium-owned changes above, the avoided `into_bytes(&self)` clone and the explicit storage PRK wipe; the caller-owned output buffer of `hmac_tag` was already explicitly wiped before A-3.5): the `Sha256` hasher and `Sha256VarCore` state (`sha2-0.11.0/src/block_api.rs:89-101`, only with `sha2/zeroize`), the `BlockBuffer` (`block-buffer-0.12.1/src/lib.rs:424-442`) and the bytes owned by HMAC's `CtOutput` (`digest-0.11.3/src/mac.rs:241-253`), both via `digest/zeroize`. The owned inner and outer SHA state and block buffer of a keyed `Hmac<Sha256>`, including those fields in each HMAC context cloned by HKDF expand, wipe through field drop glue (`Hmac` has no `ZeroizeOnDrop` of its own). HKDF's ordinary `T(n)`, `output` and `prev` locals are not covered. Each direct `Sha256` has the same state/buffer cleanup; `record_digest` hashes the session checkpoint record, which holds ratchet secrets. `hmac/zeroize` alone does not wipe the hash state: it reaches only `digest`. **Bytes unchanged:** golden outputs captured from the production functions at `31f7915` before the change and pinned in `ratchet/golden.rs`, `x3dh/golden.rs` (with and without an OPK), `hybrid/golden.rs`, `core-storage/src/golden.rs` (subkey, key-name hash, key-name encryption subkey) and `durable/golden.rs` (`record_digest`, lengths around the block boundary); each also equals an independent recomputation with Python's `hmac`/`hashlib` (run once in the session, the script is not committed); RFC 4231, RFC 5869 and FIPS 180-4 vectors (`hash_contract.rs`); the earlier fixtures of previous implementations (a ratchet conversation with skipped keys and a DH step, checkpoints, the legacy databases of `legacy_upgrade`) still pass. **Storage:** a database written by the base commit with a fixed key (10 values, several namespaces) was opened by this tree — file bytes unchanged by the read, every value and namespace listing identical — then written to, and the base build read the result (RUNTIME_VERIFIED, scratch harness, not committed). **Pins:** `sha256_hasher_is_wiped_on_drop`, `keyed_hmac_parts_and_its_tag_are_wiped_on_drop` (compile only with the features), `the_hkdf_key_is_always_wiped_and_the_hmac_tag_is_never_copied` and `the_hkdf_key_is_always_wiped` (source text: spelled forms only), `tests/feature_graph.rs` (`cargo tree --offline`: the features and the lines per crate). Temporary controls: no `hmac/zeroize` — caught by `feature_graph` only (the type pins cannot see it, because `sha2/zeroize` enables the same `digest` feature); no `sha2/zeroize` — caught by the type pins and `feature_graph`; `Hkdf::new` restored, `into_bytes` added — caught by the source guards; a clone spelled `as_bytes().clone()` — **not caught**; a changed HKDF info, salt or HMAC tag — caught by the goldens. **Limits:** cleanup covers the named hash-state, buffer and `CtOutput` owners, not every secret-derived value; H-9 lists the remaining ordinary locals. Source-visible absence of cleanup does not establish physical recoverability after return. Green tests and a successful build do not show that memory is erased on a device. The old `hmac 0.12.1`, `hkdf 0.12.4` and `sha2 0.10.9` remain in the graph for third-party consumers (see H-9). *(Note 2026-11-24: `sha2` is 0.11.1 since PR #262, the cleanup cited above is unchanged in it, and `hkdf 0.12.4` has left the graph; see "Update 2026-11-24: arti 0.48 in core-transport". Status unchanged.)* |
| **A-3.6** | Hand-written Kotlin draft stringification (ARCIUM-H15-KOTLIN-DRAFT-STRINGIFICATION-HARDENING-A3.6): `ChatState`, a hand-written Kotlin `data class`, printed the user's unsent draft (`input: String`) from its generated `toString` and string templates (H-15). A-3 itself stays PARTIAL (H-9 residuals and others below); A-3.1…A-3.5 are unchanged by this stage. | **FIXED — merged** in PR #112 (merge commit `62fbf550f0973b77caf7303385a0a6e7a1ee398c`) — verified at code commit `43f196f` (the later commit in the PR, its final HEAD `e530ae9`, changed only this file) | **Observed before** (`main` @ `5cf2770`: the `ChatState` source text with the Kotlin that `uniffi-bindgen` 0.28.3 generates from that commit, compiled with Kotlin 2.0.21 and run on the JVM; RUNTIME_VERIFIED): `ChatState(input = canary).toString()` and `"$state"` both printed `input=<canary>`. **Change:** `ChatState` stays a `data class` and overrides `toString` to print `input=<redacted>` and the other fields as before (`android/app/src/main/kotlin/com/arcium/messenger/ui/chat/ChatViewModel.kt:17-35`, override `:32-34`); a field added later is not printed until it is added there. `copy`, `equals`, `hashCode`, `componentN`, the `StateFlow` updates and the screen's reads of `input` are unchanged. The marker matches `Plaintext.kt`'s but is written out, because that constant is private to the `ffi` file and this stage does not change it. **Test:** `ChatStateStringificationTest` (JVM, `android/app/src/test/.../ui/chat/`): for an ASCII draft and a Unicode draft with a newline and a tab, the draft appears in no textual, byte, hex, per-line or escaped form in `toString`, `"$state"` or a list of states; empty and non-empty drafts render identically, so the length does not show; the other fields still appear; a state holding a `ChatEntry` and a `Conversation` with message plaintext prints neither the draft nor the plaintext (H-14 holds); copy, equality, hashing and destructuring behave as before. Run locally on the JVM against the generated Kotlin (5 tests, 0 failed; `GeneratedRecordStringificationTest` 4, 0 failed) and in CI by Android CI's `testDebugUnitTest`. Temporary controls (not committed): the override removed, `input` printed in it, the check reduced to `"$state"` with `input` printed, the draft's length printed, its last line printed — each caught by the test; `ChatState` made a plain `class` — caught at compile time. **Limits:** covers accidental formatting of `ChatState` only. The draft is an ordinary Kotlin `String`: nothing wipes it, and code that reads `input` (the screen does) can still log or send it; the Compose text field's own state is not covered. No production `Log.*`, `Timber`, `println` or `System.out` call exists in `android/app/src/main` or `src/debug`, and `ChatState` is read only field by field (`ChatScreen.kt`), so no leak was observed before either. `AddContactState` (`ui/contacts/AddContactViewModel.kt:17`) also has a generated `toString` over typed text — the pasted contact card and the contact's name, not message plaintext — and is recorded here, not changed. |
| **A-3.7** | Reproducible root Rust dependency graph (ARCIUM-H10-REPRODUCIBLE-RUST-DEPENDENCY-GRAPH-A3.7): the root workspace's `Cargo.lock` was git-ignored, so every CI run resolved the graph afresh (H-10). A-3 itself stays PARTIAL; A-3.1…A-3.6 are unchanged by this stage. | **FIXED — merged** in PR #114 (merge commit `8565875aec7809757e90da1ec95aab68272669de`) — verified at commits `3b1065c` and `635f3d0` (the later commits in the PR, up to its final HEAD `e266e29`, changed only this file) | **Observed before** (`main` @ `1028182`): `.gitignore` ignored `Cargo.lock` and none was tracked; Arcium CI ran `cargo test`/`clippy`/`audit` without a lockfile, and the UniFFI bridge action and the native artifact baseline ran `cargo generate-lockfile` before their `--locked` builds, locking a graph made during the run. A fresh resolution on 2026-10-04 differed from the one tested for A-3.5 on 2026-09-30 in `cc`, `lazy_static`, `libc`, `mio` and `tokio` (patch releases; no security-critical crate). **Policy:** the workspace builds an Android native library (`mobile-ffi`, cdylib/staticlib) and a relay binary; no crate is published and no workflow publishes one, so one tracked root lockfile is the conventional Cargo choice. **Change:** the root `Cargo.lock` is tracked (`.gitignore:2-6` keeps every other lockfile ignored); it is `cargo generate-lockfile` on the base manifests with nothing edited (502 packages, identical names, versions, features and dependency edges to the fresh base resolution). Arcium CI runs `cargo test`/`clippy` with `--locked`, `cargo audit --file Cargo.lock`, and a final step that fails if `Cargo.lock` is untracked or was rewritten (`.github/workflows/arcium-ci.yml:26-39`); the bridge action requires the tracked file, builds `--locked` and fails if it changed (`.github/actions/uniffi-android-bridge/action.yml:59-62, 116, 152, 159`); the native artifact baseline requires it and builds `--locked` (`native-artifact-baseline.yml:56-58, 125, 185`); the host relay and peer builds of the instrumentation and two-device workflows use `--locked`; the native bridge, instrumentation and two-device workflows also run when only `Cargo.lock` changes (their path filters list it next to `Cargo.toml`). The bindgen helper's `cargo generate-lockfile --manifest-path "${HELPER_DIR}/Cargo.toml"` (`action.yml:94`, `native-artifact-baseline.yml:103`) locks a scratch crate whose only dependency is `uniffi` at the version read from the root lock; it is not part of the root graph. `arcium-psi` is a separate workspace and keeps its own (ignored) lockfile. **Graph:** `hmac 0.13.0` (`zeroize`), `hkdf 0.13.0`, `sha2 0.11.0` (`alloc`, `default`, `oid`, `zeroize`), `digest 0.11.3` (`zeroize`), `block-buffer 0.12.1` (`zeroize`), `zeroize 1.9.0`, with the old 0.12/0.10 lines beside them — the A-3.5 basis. **Verified** (cargo 1.94.1): a fresh clone of the commit has the tracked file; `cargo test --workspace --locked` (including the A-3.5 golden, `hash_contract` and `feature_graph` tests and the storage fixtures) and `cargo clippy --workspace --locked -- -D warnings` pass and leave it unchanged; with a manifest requirement changed or the file removed, `--locked` fails; a different committed lock decides the versions built (`tokio 1.53.1` instead of the newest compatible `1.53.2`); `cargo audit` 0.22.2 scans this file (502 packages) and exits 0 with four `unmaintained` warnings — `bincode` 1.3.3 and 2.0.1, `paste`, `ring` 0.16 — under the two advisories `.cargo/audit.toml` already ignores. Temporary controls (not committed): the lockfile untracked again — caught (`--locked` cannot create it; the tracked check fails); a root `cargo generate-lockfile` restored after the registry moved — caught by the rewrite check (with no newer releases it leaves the file unchanged); a root command without `--locked` on a stale manifest — caught by the rewrite check; an `hmac` checksum edited in the lock, or an `hmac` requirement the lock cannot satisfy — `--locked` fails. **Limits:** pins the root Rust dependency graph only. The Rust toolchain (`stable`), `cargo-audit`, the GitHub actions, the NDK and the npm/Gradle graphs are not pinned by this; builds are not claimed to be bit-for-bit reproducible. A dependency update is now an explicit `Cargo.lock` diff and needs its own review. |

---

## H-series: memory-hygiene follow-ups (H-1, H-3, H-4, H-5 closed by A-3.1, H-11, H-12 by A-3.2, H-13 by A-3.3 and H-14 by A-3.4, merged; H-9 partially fixed by A-3.5, merged; H-15 by A-3.6, merged; H-10 by A-3.7, merged; the rest recorded, not fixed)

Surfaced while reviewing A-3 and while reconciling this file. Rows H-1, H-3, H-4 and H-5
describe the state of `main` @ `087b9c8` and are closed by A-3.1 (see that row), merged in PR #105
(`6266c0b`). Rows H-11 and H-12 are closed by A-3.2, merged in PR #106
(`e5331ed`). Row H-13 is closed by A-3.3, merged in PR #107 (`a96d72b`). Row H-14 is closed by
A-3.4, merged in PR #108 (`5d61d5a`). Row H-9 is **partially** fixed by A-3.5, merged in PR #110 (`f72043e`); its residuals stay open (see that row). Row H-15 is closed by A-3.6, merged in PR #112 (`62fbf55`). Row H-10 is closed by A-3.7, merged in PR #114 (`8565875`).
The other rows are **recorded only, and none of them is claimed fixed**. Severity is the reviewer's estimate;
each needs a local attacker who can later read process memory (a core dump, swapped pages,
a memory-disclosure bug). Labels: `SV` SOURCE_VERIFIED, `INF` INFERRED, `NV` NOT_VERIFIED.

| ID | Sev | Item | Anchor (`main` @ `087b9c8`) | Label |
|----|-----|------|-----------------------------|-------|
| **H-1** | LOW · **FIXED — merged (A-3.1, PR #105)** | `core-storage` subkeys are plain `[u8; 32]` wiped by a manual `zeroize()` call that an early `?` or a panic skips: `decrypt_key_name` (`?` at `:344`, wipe at `:345`), `encrypt` (`?` at `:369`, wipe at `:374`), `decrypt` (`?` at `:393`, wipe at `:395`). `subkey` and `key_name_encryption_subkey` return plain arrays (`:310-315`, `:349-354`). The master key itself is wiped in `Drop` (`:400-403`). | `crates/core-storage/src/lib.rs` | SV |
| **H-2** | LOW | `RescueCipher` keeps its key in a plain `[u8; 32]` with no `Drop`, and `from_shared_secret` copies it from the caller's array. This is the M-3 stub (`CLAUDE.md`, «Постоянные ограничения»); the real cipher would need its own review, and this row does not authorize replacing it. | `crates/core-crypto/src/rescue.rs:21-27` | SV |
| **H-3** | LOW · **FIXED — merged (A-3.1, PR #105)** | `AliceSession` derives `Debug` and holds `root_key: Zeroizing<[u8; 32]>`; `Zeroizing` derives `Debug` and prints its contents (zeroize 1.9.0 `src/lib.rs:602`), so formatting an `AliceSession` with `{:?}` prints the root key. No call that formats it was found in `mobile-ffi` or `x3dh.rs` (latent, not exploited). `BobSession` has no `Debug`. | `crates/core-crypto/src/x3dh.rs:103-106` | SV |
| **H-4** | LOW · **FIXED — merged (A-3.1, PR #105)** | `ArciumCore::new` wraps the caller's `Vec` in `Zeroizing`, but copies the key into a plain local `[u8; 32]` (`try_into`) and passes that array by value to `EncryptedStore::open`; the local is not wiped. | `crates/mobile-ffi/src/lib.rs:570-574`, `crates/core-storage/src/lib.rs:65` | SV |
| **H-5** | LOW · **FIXED — merged (A-3.1, PR #105)** | `StagedTransition<T>` wipes the ratchet and the record when dropped without commit, but `output: T` is not wrapped: for a staged receive, `T` is the decrypted plaintext as a plain `Vec<u8>`, so the plaintext of an abandoned transition is not wiped. | `crates/core-protocol/src/durable.rs:522-529, 723` | SV |
| **H-6** | LOW | The skipped-key store is an `IndexMap` of `Zeroizing` keys; `swap_remove`, `shift_remove_index` and growth move entries bitwise, so stale copies can remain in spare capacity or in a freed buffer. | `crates/core-crypto/src/ratchet.rs:108, 233, 342` | INF (from `indexmap`'s design; not observed) |
| **H-7** | LOW | Moves of secret arrays and `StaticSecret::from(*bytes)` copy the secret onto the stack (`x25519` takes the array by value); the source array is then wiped, the stack copy is not. | `crates/core-crypto/src/ratchet/checkpoint.rs:324`, `crates/core-crypto/src/hybrid.rs:120`, `crates/mobile-ffi/src/lib.rs:377, 387, 610` | SV (copy sites); INF (that the stack copies persist) |
| **H-8** | INFO | Wipes run on drop and on unwinding only. `abort`, `SIGKILL`, `mem::forget`, swap and core dumps are outside them. Root `Cargo.toml:28-32` (`[profile.release]`) sets no `panic` key, so the default (unwind) applies. Not checked: that the Android release `.so` retains `zeroize`'s volatile writes, and the memory of a real device. | root `Cargo.toml:28-32` | SV (profile); **NV** (release-`.so` behaviour, device memory — would need disassembly and memory forensics) |
| **H-9** | LOW · **PARTIALLY_FIXED** (A-3.5, merged in PR #110 (`f72043e`)) | Secret-derived state inside `hmac`, `hkdf` and `sha2`. **Before A-3.5** (`hmac 0.12.1`, `hkdf 0.12.4`, `sha2 0.10.9`) these crates provided no internal zeroization or drop cleanup. Arcium's `hmac_tag` already explicitly wiped its caller-owned output after copying it. **After A-3.5** (`hmac 0.13.0` and `sha2 0.11.0` with `zeroize`; `hkdf 0.13.0` benefits transitively and has no `zeroize` feature of its own; exact graph in A-3.5) the owned SHA state, block buffer and `CtOutput`-owned HMAC tag bytes wipe on drop, and Arcium explicitly wipes the caller-owned PRK returned by `Hkdf::extract` at every audited Arcium extract call site (`kdf_rk`, `derive_root`, `combine_secrets` and, new in A-3.5, the three storage KDF derivations). This covers that returned PRK buffer only: not internal HMAC/HKDF state, not other PRK-derived copies, not moved-from locations, and not HKDF's `T(n)`, `prev` and `output` locals (residuals below). **Source-visible residuals (SV, audited stock versions):** ordinary locals without cleanup: the normalised key block and its `⊕ ipad` / `⊕ opad` variants (`hmac-0.13.0/src/utils.rs:9-32`, `block_api.rs:53-69`); the inner digest `hash` in `finalize_fixed_core` (`block_api.rs:81-90`); the ordinary `CtOutWrapper::full_res` digest copy, copied into the final output without local cleanup (`digest-0.11.3/src/block_api/ct_variable.rs:103-116`); HKDF's `T(n)` blocks, `prev` and `output` in `expand_multi_info` (`hkdf-0.13.0/src/lib.rs:135-162`); compression message schedules and working locals in software/hardware backends (e.g. `sha2-0.11.0/src/sha256/soft/unroll.rs:46`, `x86_sha.rs:46`, `aarch64_sha2.rs:13`). Each HKDF expand HMAC context clone has cleanup of its owned SHA state and block buffer, not of these ordinary output locals. **Inferred persistence (INF):** moved-from stack slots, register spills and stale stack copies may retain material, including `Output` moved through `Mac::finalize` (`digest-0.11.3/src/mac.rs:97-99`) and out of `Hkdf::extract` (`hkdf-0.13.0/src/lib.rs:61-65, 117-121`). Arcium wipes the returned PRK owner; persistence in other locations after return is inferred, not observed. Source-visible absence of cleanup does not prove physical recoverability. **Not verified (NV):** actual post-operation Android/device memory contents, compiler/register erasure and physical RAM behaviour. Also: `hkdf` has no `zeroize` feature of its own and relies on `hmac`/`sha2` features Cargo unifies, and `hmac/zeroize` alone reaches only `digest`, so the hash-state wipe depends on `sha2/zeroize` (pinned by `feature_graph` and `hash_contract`, see A-3.5); before A-3.7 the untracked root lockfile allowed a fresh compatible resolution — patch releases within the declared semver ranges and changes to transitive versions — so the exact audited implementation source was not permanently pinned (H-10); since A-3.7 the root `Cargo.lock` is tracked, root CI and native builds use it with `--locked`, and a dependency-version change needs an explicit reviewed lockfile diff. This does not pin the toolchain or compiler, nor what a future dependency release would contain. **Old lines still in the graph, for other consumers:** `hmac 0.12.1` (`hkdf 0.12.4`, `rfc6979`, `tor-proto`), `hkdf 0.12.4` (`tor-proto`) and `sha2 0.10.9` (`ed25519-dalek`, `p256`/`p384`/`p521`, `rsa`, `ssh-encoding`, `ssh-key`, `tor-llcrypto`), with no `zeroize` feature. They are not among the audited call sites, but `ed25519-dalek` expands the Ed25519 signing key with `sha2` 0.10's `Sha512` (`ed25519-dalek-2.2.0/src/signing.rs:23, 318`), and Arcium generates that key (`crates/mobile-ffi/src/lib.rs:207`): recorded, not fixed. **Standalone production `Sha256` uses:** only `record_digest` (`core-protocol/src/durable.rs:309`) hashes secret-bearing input (the session checkpoint record) — its hasher is now wiped; the others hash public or non-key data (`spk_id`, `local_session_handle`, `message_id`, the handshake dedup key, the contact-card fingerprint, `hash_contact` over a phone number) and their outputs are intentionally kept. The stock upstream versions audited here leave the listed residuals. Complete safe-Rust source-level remediation has not been established and has not been proven impossible (**UNCERTAIN**); further work requires a separate owner-scoped investigation, with no technical solution selected here. See F-8. *(Note 2026-11-24: `sha2` is 0.11.1 since PR #262, two of the three `sha2` backend lines cited above moved, and the consumers of the old lines changed; see "Update 2026-11-24: arti 0.48 in core-transport". Status unchanged.)* | `Cargo.toml:20-22`; `crates/core-crypto/src/ratchet.rs:388-421`, `x3dh.rs:200-223`, `hybrid.rs:158-188`; `crates/core-storage/src/lib.rs:298-302` | SV (named owner cleanup and source-visible ordinary locals without cleanup in the resolved versions); INF (persistence of moved-from stack/register copies); RUNTIME_VERIFIED (byte compatibility, see A-3.5); NV (post-operation device memory, compiler/register erasure and physical RAM behaviour) |
| **H-10** | LOW (supply chain) · **FIXED — merged (A-3.7, PR #114)** | **Before A-3.7:** `Cargo.lock` was git-ignored (`.gitignore:2`), so the repository did not pin the versions of `hmac`, `hkdf`, `sha2`, `zeroize` or anything else; each CI run resolved afresh, and `cargo audit` audited whatever was resolved then. Any statement about a third-party crate version in this file is about the versions named in the evidence basis, not about what the repository guarantees. A-3.5's `tests/feature_graph.rs` validates the resolved build's dependency lines and features, not future upstream implementation semantics. The direct declarations `hmac = "0.13"`, `hkdf = "0.13"` and `sha2 = "0.11"` permit compatible patch releases within those semver ranges, not arbitrary new direct minor/major lines; transitive dependency versions may also change. The exact audited implementation source was therefore not permanently pinned. **After A-3.7** (see that row): the root `Cargo.lock` is tracked, every root CI and native build uses it with `--locked`, `cargo audit` reads it, and a rewritten or untracked lockfile fails CI; a dependency change is a reviewed `Cargo.lock` diff. The toolchain, `cargo-audit`, actions and non-Rust graphs are not pinned by it. | `.gitignore:2-6`; `Cargo.lock`; `.github/workflows/arcium-ci.yml:26-39` | SV; RUNTIME_VERIFIED (local, see A-3.7) |
| **H-11** | LOW · **FIXED — merged (A-3.2, PR #106)** | Recorded during A-3.1, not fixed: several types derive `Debug` over plaintext, so formatting them prints message text — `core_protocol::messaging::IncomingMessage` (`Zeroizing<Vec<u8>>`, whose `Debug` prints its contents), the FFI `IncomingMessage` and `ReceivedText` (plain `Vec<u8>`), and `Payload::Text`. No call that formats them was looked for beyond the A-3.1 scope. | `crates/core-protocol/src/messaging/types.rs:48`, `crates/mobile-ffi/src/messaging_api.rs:111`, `crates/mobile-ffi/src/network.rs:63`, `crates/mobile-ffi/src/network/wire.rs:89` | SV (derives); NV (whether any is formatted) |
| **H-12** | LOW · **FIXED — merged (A-3.2, PR #106)** | Recorded during A-3.1, not fixed: `DoubleRatchet::decrypt` returns the plaintext as a plain `Vec<u8>` to its caller (`crates/core-crypto/src/ratchet.rs:205`); the durable layer wraps it at once, but any other caller owns an unwiped buffer. | `crates/core-crypto/src/ratchet.rs:205-222` | SV |
| **H-13** | LOW · **FIXED — merged (A-3.3, PR #107)** | Recorded during A-3.2, not fixed: the outgoing text passes through ordinary `Vec<u8>` owners before `send_message` wraps it on entry — `Payload::Text(text).encode().to_vec()` in `send_text`, and `e.text.to_vec()` when a queued chat text is re-sent from `refresh`. The windows are short and hold no fallible step of their own, but they are ordinary owners of application plaintext. | `crates/mobile-ffi/src/network.rs:227`, `crates/mobile-ffi/src/network/chat.rs:828` | SV |
| **H-14** | LOW · **FIXED — merged (A-3.4, PR #108)** | Recorded during A-3.2; confirmed on the generated Kotlin (see A-3.4): the records UniFFI generates are `data class`es whose `toString` prints every property — `ChatEntry.text` (`String`) verbatim, `IncomingMessage.plaintext` and `ReceivedText.text` (`ByteArray`) as decimal bytes — and `ReceiveResult`, `Conversation` and lists that hold them print it too. No `Log.*`, `Timber`, `println` or `System.out` call exists in `android/app/src/main` or `src/debug`, so nothing formatted them: a type-level exposure, not an observed log leak. | `android/app/build/generated/rustBridge/kotlin/uniffi/arcium_core/arcium_core.kt` (build output, generated at `main` @ `a96d72b`) | RUNTIME_VERIFIED (JVM, Kotlin 2.0.21); Android runtime: see A-3.4 |
| **H-15** | LOW · **FIXED — merged (A-3.6, PR #112)** | Recorded during A-3.4; reproduced on the JVM and fixed by A-3.6 (see that row): `ChatState`, a hand-written Kotlin `data class`, holds the user's unsent draft in `input: String`, so its generated `toString` printed the draft. A-3.6 makes it print `input=<redacted>`; the draft is still an ordinary `String` and is not wiped. It also holds `List<ChatEntry>` and `Conversation`, which A-3.4 made print `<redacted>` for the message text. No `Log.*`, `Timber`, `println` or `System.out` call exists in `android/app/src/main`, so nothing formats it today. Not generated by UniFFI, so outside A-3.4's check. | `android/app/src/main/kotlin/com/arcium/messenger/ui/chat/ChatViewModel.kt:17-35` | SV; RUNTIME_VERIFIED (JVM, see A-3.6) |

---

## Scope notes (clarifications that are not findings)

**N-1 · Raw `DoubleRatchet` counters versus durable messaging bounds.** The two are
different things, and neither statement should be quoted without the other.

- *Raw ratchet.* `DoubleRatchet` increments its counters with an unchecked `+= 1`:
  `self.ns += 1` (`crates/core-crypto/src/ratchet.rs:192`) and `self.nr += 1` (`:255`,
  `:302`). The workspace sets no `overflow-checks` (`Cargo.toml:28-32`), so in a release
  build the counter wraps and in a debug build it panics. The raw type therefore has no
  bound of its own near `u32::MAX`.
- *Durable bound.* The durable path refuses states past the limit instead of persisting
  them: `check_state` (`crates/core-crypto/src/ratchet/checkpoint.rs:150-191`) returns
  `CounterExhausted` for `ns == u32::MAX` (`:184`) and for `nr > MAX_RESUMABLE_NR`
  (`:187`, `MAX_RESUMABLE_NR = u32::MAX - MAX_SKIP - 1`, `:115`), on encode and decode
  (doc `:64-80`). A receive that would move `nr` past the bound still succeeds inside the
  ratchet; it is the checkpoint of the resulting state that is refused, so a durable session
  rejects that transition rather than persisting it.
- *What is not established.* That every path which holds a `DoubleRatchet` goes through the
  durable layer (tests build raw ratchets directly, e.g. `core-protocol/src/checkpoint.rs:309`),
  and that a message that overflows a raw ratchet before authentication is harmless in a
  debug build — the checkpoint module's own doc says such a header could panic one
  (`crates/core-crypto/src/ratchet/checkpoint.rs:70-73`). This note records the distinction; it does not open or close a
  finding.

**N-2 · What the reviews may and may not do with this file.** `arcium-security-review` and
`engineering-code-review` are separate procedures and stay separate: this file is input to
the first as leads and as the record of accepted residuals, and it is never a substitute
for reading the diff. A documentation review of this file checks that the rows agree with
the source at the cited SHA; it is not evidence that the implementation is secure.

---

## Non-F-series items (surfaced during recent work)

| ID | Description | Status | Evidence (`main` @ `087b9c8`) |
|----|-------------|--------|-------------------------------|
| **X-1** | Identity-persistence silent key-loss (the Kotlin-side consequence of F-9: a `None` on wrong-key/`NotFound` leads onboarding to generate and overwrite a real identity) | **MERGED** *(corrected 2026-09-29; was «FIXED / UNMERGED»)* | PR #48 merged (`98ad3a2`). `ArciumCore.kt:309` now has a real `openEncryptedDb`; `ArciumApp.kt:20` calls it with the master key from `security/MasterKeyProvider.kt`. Read statically; the startup flow was not exercised here (the emulator manual test the old row waited for is not evidenced in this snapshot), and the Rust-side gap of F-9 is unchanged. **Cross-ref (F-9, 2026-10-06):** that Rust-side gap is closed by PR #120 (`e0e825c`): read errors no longer become "no identity", identity creation no longer overwrites a stored record, and Android no longer starts onboarding after a failed read. A wrong, lost or replaced master key still reads as "no identity", and onboarding then creates a new identity in a separate row (see F-9, scope). This row's status is unchanged. **Cross-ref (F-9, 2026-11-06):** the Kotlin start-up path no longer creates a new master key for an existing store whose blob is missing, and an unreadable blob blocks start-up instead of crashing (PR #133, `090bb17`; see "Update 2026-11-06: master-key loss at start-up"). This row's status is unchanged. |
| **X-2** | `require_identity()` — a private helper — was exported to Kotlin as callable `requireIdentity(): Identity` because it sat inside a `#[uniffi::export] impl` block | **FIXED / MERGED** | PR #50 (merge `492c5d1`). `require_identity` is defined at `crates/mobile-ffi/src/lib.rs:971`, inside a plain `impl ArciumCore` (`:932`) separate from the exported block (`:563-564`). (The 2026-07-19 row cited `:389-390`; the code has moved.) |
| **X-3** | **Lesson (guidance, not a bug):** `#[uniffi::export]` applies to an entire `impl` block — every method in it is exported regardless of Rust `pub`/private visibility. Private helpers must live in a separate non-exported `impl` block. | **N/A (standing guidance)** | Root cause of X-2. Applies to any future `#[uniffi::export] impl` in `crates/mobile-ffi`. |

---

## Reconciliation 2026-11-06 (`main` @ `7455da8`)

**TARGET_SHA: `7455da8440521a14bbb09baf8d646243a8b5d6c6`** (the merge of PR #130), resolved
from `origin/main` at the start of this pass and re-checked unchanged before it was written.
This pass covers the PRs merged since the last tracker update (PR #121, `620aea7`) and five
historical leads. Every other row keeps the SHA and evidence it cites; this pass did not
re-check them.

### Evidence basis

All commands ran on 2026-11-06 in a disposable clone of TARGET_SHA:

- `cargo test --workspace --locked`: exit 0. 443 passed, 0 failed, 3 ignored:
  - core-crypto: 105 unit tests and 2 `feature_graph` tests;
  - core-protocol: 117 unit tests and 4 doctests;
  - core-storage: 43 (+2 ignored);
  - core-transport: 5 (+1 ignored);
  - mobile-ffi (`arcium_core`): 150;
  - relay: 17.
- `cargo audit --file Cargo.lock` (cargo-audit 0.22.2, advisory-db `26fd2d43` of
  2026-11-05, 1409 advisories, 502 crates): exit 0, 0 vulnerabilities, 6 allowed warnings.
- Five temporary probe tests, run and then removed again. They are not part of the test suite:
  - three in core-storage, for D-009;
  - two in mobile-ffi, for D-007.
- One bounded run of the ignored test `new_fails_gracefully_without_tor` (D-008).
- A shell reproduction of the license pipeline (D-011).
- A Python re-computation of `hash_contact` (D-010).

Each item below states its exact command or outcome. The evidence labels are those of
`CLAUDE.md`.

The exact probe code, the commands to re-run every reproduction and their full output
are kept in [`RECONCILIATION-2026-11-06-PROBES.md`](./RECONCILIATION-2026-11-06-PROBES.md).
That file is documentation: nothing in it is compiled or run by `cargo test` or CI.

### Merged since the last tracker update

| PR | Merge | What changed (source read at the merge) | Tracker implication |
|----|-------|------------------------------------------|---------------------|
| #122 | `88e6957` | `Cargo.lock` only: rustls 0.23.45 → 0.23.46, plus one `tempfile` edge, `getrandom` 0.4.3 → 0.3.4 (`git diff 88e6957^1 88e6957`). | None for any row. The advisory IDs RUSTSEC-2026-0346…0349 come from the PR title; this pass did not look them up. The local `cargo audit` above reports no vulnerability at TARGET_SHA (RUNTIME_VERIFIED). |
| #125 | `2e09986` | `Cargo.lock`: ctutils 0.4.4, rustls-webpki 0.103.16, zstd 0.14.3, zstd-safe 8.2.0, zstd-sys 2.1.2. `.cargo/audit.toml` adds an ignore for RUSTSEC-2026-0387 (crypto-bigint 0.5.5), valid only together with the guard `.github/scripts/check_rustsec_2026_0387.py`. `arcium-ci.yml:48-51` runs the guard's self-test, then the guard, before `cargo audit` (`:54-58`). | None for an F/A/H row. The new ignore is a supply-chain residual alongside the two in `CLAUDE.md`. The guard's own result on TARGET_SHA was not run in this pass: it is a CI step (NOT_VERIFIED here). |
| #127 | `a075240` | Delivery consistency, recorded as **X-4** below. | New row X-4. |
| #123, #124, #128, #129, #130 | — | `.claude/` (hooks, QC, skills, agents, commands, settings), `CLAUDE.md`, a QC test-scope script and job in `arcium-ci.yml`, `docs/QC-V1-OPERATIONS.md` (`git diff --name-only` of each merge). | None. Agent tooling only; no runtime code changes. |

### Historical leads D-007 … D-011

These leads come from the `continuity` branch (`decisions.md`, recorded 2026-10-19 at
`fb9cf32`). That record is not stored on `main`. Here it was used as a lead only: each item
below was re-derived at TARGET_SHA. None of them is a new vulnerability class. Three refine
the stated scope of existing rows (F-9, F-10, F-15), and two are recorded here for the
first time.

**D-007 · Missing `master_key.blob` with an existing database → new identity.** Home:
**F-9 scope (unresolved residual)**. F-9's status is unchanged.
- *Source (SOURCE_VERIFIED).*
  - `MasterKeyProvider.getOrCreateMasterKey`
    (`android/app/src/main/kotlin/com/arcium/messenger/security/MasterKeyProvider.kt:42-68`)
    decides between unwrap and create only on `blobFile.exists()` (`:45`). It never looks at
    `arcium.db`.
  - `ArciumApp.onCreate` opens `arcium.db` with whatever key it gets (`ArciumApp.kt:18-20`).
  - Records are found under a master-key-derived name (`storage_key`,
    `crates/core-storage/src/lib.rs:330`; `get_row` `:450`). So under another key the
    identity read is `NotFound`, which `identity_from_record` maps to `Ok(None)`
    (`crates/mobile-ffi/src/lib.rs:243-246`).
  - `IdentityRepository.load` turns that into `Absent`
    (`android/.../data/IdentityRepository.kt:31-32`). `IdentityGate` routes `Absent` to
    onboarding (`ui/navigation/IdentityGate.kt:58`). Onboarding's `createOrLoadExisting`
    (`data/IdentityRepository.kt:44`, `ui/onboarding/OnboardingViewModel.kt:33`) reaches the
    create-only `save_identity` (`lib.rs:640`). Under the new key that finds no record, so it
    writes a second identity row.
- *The three cases are distinct:*
  1. **Missing blob:** a new random master key is created silently (`:51-58`). That is the
     path above.
  2. **Corrupted blob:** the version and length check (`:97-99`) or the GCM tag
     (`cipher.doFinal`, `:104`) throws. `ArciumApp.onCreate` does not catch it, so startup
     fails visibly (INFERRED from the source; not run on Android). Nothing is created.
  3. **Wrong key:** for example, the Keystore alias is gone and `getOrCreateWrapKey`
     (`:70-87`) generates a new wrap key. The existing blob then fails GCM authentication and
     throws as in case 2 (INFERRED from source). A wrong key that reaches Rust some other way
     behaves like case 1 (INFERRED from the storage lookup above).

  Separately, a corrupted identity *row* under the right key is `IdentityUnreadable`, not
  absence (probe 2 below; the F-9 tests).
- *Runtime (RUNTIME_VERIFIED, Rust level only).* Temporary probe
  `probe_new_master_key_on_existing_db_reads_as_no_identity_and_allows_a_second_identity`
  (mobile-ffi):
  - save an identity under key A, open the same file under key B;
  - `load_identity` → `Ok(None)`, and `save_identity` of a new identity → `Ok`;
  - reopen under key A → the original identity is still present.

  The old identity is orphaned, not deleted. Probe `probe_corrupted_identity_row_is_an_error`:
  a zeroed row under the right key gives `Err(IdentityUnreadable)`. The committed test
  `core_with_wrong_key_fails` (`lib.rs:1108`) passed in the workspace run and pins the
  `Ok(None)` half.
- *Not verified.* The Android path end to end: deleting the blob on a device or emulator
  and observing onboarding. Also cases 2 and 3 at runtime, which need the Android Keystore.
- *Smallest next task.* Task 1 below.

**D-008 · `TorTransport::new` has no bootstrap timeout.** Home: **F-15 scope**. F-15's
status is unchanged.
- *Source (SOURCE_VERIFIED).* `TorTransport::new` awaits
  `TorClient::create_bootstrapped(TorClientConfig::default())` with no timeout
  (`crates/core-transport/src/lib.rs:23-27`). It ignores `_state_dir` (`:23`; F-15(b)) and
  hard-codes `"TODO.onion"` (`:30`). *(Note 2026-11-24: `state_dir` is used since PR #265; see "Update 2026-11-24: Tor connector in core-transport".)*
- *Production caller.* None. *(Note 2026-11-27: `TorTransport::new` still has none, but since PR #275 the app's core calls `TorConnector::bootstrap`, which builds the client through `TorTransport::create` with the same bound, for a relay at an onion address; see "Update 2026-11-27: Tor for onion relays".)*
  - `mobile-ffi` lists `core-transport` as a dependency (`crates/mobile-ffi/Cargo.toml:16`),
    but nothing under `crates/mobile-ffi/src` names `core_transport` or `TorTransport`
    (`grep`, no match).
    *(Note 2026-11-20: no longer a dependency at all, PR #232; see "Update 2026-11-20: core-transport not a mobile-ffi dependency".)*
  - The Kotlin `startTorTransport` throws `NotImplementedError`
    (`android/.../ffi/ArciumCore.kt:263-269`). *(Note 2026-11-28: removed by PR #276; see "Update 2026-11-28: Tor route in Settings and core fixes".)*
  - Today the missing timeout cannot block any shipped path (SOURCE_VERIFIED by the absence
    of callers). *(Note 2026-11-27: since PR #275 the bound applies on a shipped path; see "Update 2026-11-27: Tor for onion relays".)*
- *Runtime (RUNTIME_VERIFIED, cause INFERRED).*
  `timeout 120 cargo test --locked -p core-transport new_fails_gracefully_without_tor -- --ignored`
  printed `has been running for over 60 seconds` and was killed by `timeout` (exit 124). The
  test binary ran about 99 s of the 120 s; the build took 21 s. So the call did not return
  an error within that bound in this sandbox. That the cause is the missing timeout, and not
  this sandbox's network policy, is inferred.
- *Smallest next task.* Task 3 below. It is not urgent while there is no caller.

**D-009 · Storage rollback.** Home: **F-10 scope** and `docs/S2-B2-DURABLE-MESSAGING.md`
§8. F-10's status is unchanged. Three different properties need to be kept apart.
- *Single-record rollback (RUNTIME_VERIFIED).* A row's value is AEAD-encrypted under a
  per-key subkey, with only the key name as AAD (`crates/core-storage/src/lib.rs:406-419`).
  No version or counter is bound into it. Probe `probe_single_record_rollback_is_accepted`:
  - write `session:bob` = v1 and keep the raw row;
  - write v2, then put the old ciphertext back into the same row with plain SQL;
  - `get` → v1, accepted without error.
- *Cross-record substitution is refused (RUNTIME_VERIFIED).* Probe
  `probe_cross_record_swap_is_refused` copies one record's ciphertext into another record's
  row. That read fails with `Decryption`; the untouched record still reads.
- *Whole-file rollback (RUNTIME_VERIFIED).* Probe `probe_whole_file_rollback_is_accepted`:
  - snapshot the file after v1, then write v2 and a new record;
  - copy the snapshot back and reopen;
  - result: v1, and the new record is `NotFound`.

  This is the case F-10 and S2-B2 §8 (`docs/S2-B2-DURABLE-MESSAGING.md:351`, "malicious
  rollback (older database file) — not provided; needs an external authority") already list
  as not covered. The single-record case is a narrower attack: it needs write access to one
  row, not a whole-file restore. It was not spelled out in the F-10 row before.
- *Crash consistency is a separate property.* It is covered by rollback-journal mode,
  `synchronous = EXTRA` and the transaction rules (`crates/core-storage/src/lib.rs:87-122`;
  S2-B2 §§3, 7, 8). None of the probes above concerns it. Passing crash tests says nothing
  about rollback resistance, and the reverse is also true.
- *Not established.* Whether a single-record rollback of a ratchet or outbox record can be
  turned into nonce or key reuse. This pass did not analyse it (NOT_VERIFIED); it belongs to
  the design decision in task 4. No witness or other trust mechanism is selected here.

**D-010 · No phone normalization before `hash_contact`.** Home: **scope note N-3** below.
This is a behaviour and compatibility fact, not a vulnerability.
- *Source (SOURCE_VERIFIED).*
  - `hash_contact` hashes the raw UTF-8 bytes it is given
    (`crates/core-crypto/src/contact_hash.rs:38-41`). The TS twin `hashPhoneWithTruncation`
    does the same (`arcium-psi/tests/src/utils.ts:8-11`).
  - There is no normalization step anywhere in Rust, TS or Kotlin (`grep` for
    `normaliz`/`E.164`, no match in source).
  - The only callers are tests and the TS test harness (`arcium-psi/tests/src/*.ts`). There
    is no production caller in `crates/` or `android/`.
- *Runtime (RUNTIME_VERIFIED).* A Python re-computation reproduces the canonical vector
  `+1234567890` → `5364562789390625858`. That vector also passes in the committed Rust test
  `matches_canonical_vector` (`contact_hash.rs:62`). The same computation gives six different
  values for `+1234567890`, ` +1234567890`, `1234567890`, `+1 234 567 890`, `+1-234-567-890`
  and the full-width digits form.
- *Compatibility (INFERRED).*
  - Normalization would be applied to the input before hashing, so the hash function, the
    truncation and the circuit's u64 comparison stay as they are.
  - Any normalization must be identical in every client. Otherwise equal contacts stop
    matching.
  - No hashes are stored today, because there is no caller, so nothing would need
    migrating.
  - This pass does not choose a format.
- *Smallest next task.* Task 5 below. It is a decision, needed before the first production
  caller.

**D-011 · SDK-license steps that mask failure.** Home: new row **A-4** below.
- *Source (SOURCE_VERIFIED).* Two steps end the license pipeline in `|| true`:
  - `.github/workflows/android-ci.yml:32`
    (`yes | $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager --licenses || true`) runs
    in the default `bash -e` shell, without `pipefail`. The step has no `shell:` key and the
    file sets no `defaults:`.
  - `.github/workflows/android-two-device-e2e.yml:90` runs after `set -euo pipefail` (`:88`).
  - `.github/workflows/native-artifact-baseline.yml:38-42` already handles this correctly:
    `set +e`, then the pipeline, then `sdk_rc="${PIPESTATUS[1]}"`, `set -e`, and
    `test "${sdk_rc}" -eq 0`.
  - The other `|| true` uses in the workflows guard log printing and process cleanup, not a
    verdict. That includes `android-instrumentation.yml:155-158`,
    `android-two-device-e2e.yml:111-140` and `arcium-ci.yml:122-124, 225-240`.
- *Runtime (RUNTIME_VERIFIED, local shell, fake `sdkmanager` that reads 4 bytes and
  exits).*

  | Shell | Fake `sdkmanager` exits 0 | Fake `sdkmanager` exits 1 |
  |---|---|---|
  | `bash -e` | step exits 0 | step exits 1 |
  | `pipefail` | step exits **141**: `yes` gets SIGPIPE, so the step fails although sdkmanager succeeded | step exits 1 |
  | either, with `\|\| true` | step exits 0 | step exits **0** |

  In `android-ci.yml:32`, `yes`'s SIGPIPE never matters, so `|| true` only hides an
  sdkmanager failure. In `android-two-device-e2e.yml:90`, `|| true` hides the producer's
  SIGPIPE and an sdkmanager failure alike. The baseline pattern keeps the sdkmanager exit
  code and drops only the producer's.
- *Impact (INFERRED).* In the two-device job the next line, `sdkmanager --install` (`:91`),
  would most likely fail on an unaccepted license, so a later step probably fails closed. In
  `android-ci` a missing license would surface in Gradle only if a component had to be
  installed. The step's own green proves nothing either way (`CLAUDE.md`, "Границы
  доказательств").
- *Smallest next task.* Task 2 below.

### Rows added by this reconciliation

| ID | Description | Status | Evidence (`main` @ `7455da8`) |
|----|-------------|--------|-------------------------------|
| **A-4** | CI integrity: the Android SDK license step ends in `\|\| true`, so a failing `sdkmanager --licenses` cannot fail the step (D-011). | **NOT-FIXED** · LOW | `.github/workflows/android-ci.yml:32`; `.github/workflows/android-two-device-e2e.yml:90`. Shell reproduction and the existing correct pattern (`native-artifact-baseline.yml:38-42`) in D-011 above. |
| **X-4** | Delivery consistency (PR #127). (a) A text missing from the outbox was read as `Delivered`. (b) `acknowledge_outgoing` and `abandon_outgoing` were exported through UniFFI. (c) `read_prior_send` read the send record and the outbox in two queries, so another connection's abandonment could be read as an acknowledgement. (d) `send_text` and `chat_send` could collide on one client id. | **FIXED — merged (PR #127, `a075240`)**, scoped as below | Neither removal is exported: `acknowledge_outgoing`/`abandon_outgoing` are `pub(crate)` in the plain `impl` (`crates/mobile-ffi/src/messaging_api.rs:194`, `:281`, `:304`), separate from the exported block (`:317-318`; X-3). `Delivered` comes only from the durable send record (`docs/NET-MESSAGING.md` §5, `:182-191`). Tests passing in the workspace run at TARGET_SHA (RUNTIME_VERIFIED): `ack_probe::neither_outbox_removal_is_exported_through_uniffi`, `ack_probe::without_a_receipt_the_network_path_never_shows_delivered`, `delivery_consistency::concurrent_sends_and_a_resolution_never_show_delivered_without_a_receipt`, `messaging::tests::concurrent::an_abandonment_from_another_connection_is_never_read_as_an_acknowledgement`, `…::concurrent_abandonments_are_never_read_as_acknowledgements`. **Scope:** no stored record is repaired; an entry already shown `Delivered` under the old rule stays so (`docs/NET-MESSAGING.md:199-202`). Two-device qualification on the new rule is open (PR #126 predates it). Physical devices are not covered. |

**N-3 · Contact-hash input is not normalized (D-010).** `hash_contact` and its TS twin hash
the exact input bytes. Formatting variants of one number hash differently (D-010 above).
This is intended behaviour of the function as written, not a defect in it. Which canonical
input form the clients must produce is an open product and protocol decision, to be made
before the first production caller. Until then the canonical standard in `CLAUDE.md`
(`u64::from_le_bytes(sha256(phone.as_bytes())[0..8])`) describes the hash, not the input
form. This note opens no finding.

### Next engineering tasks (2026-11-06)

These five supersede the ordering of the 2026-09-29 list below for new work; that list is
kept as history. Every item still needs its own owner task and PR. A fix PR must add a
counterexample that fails on the unfixed baseline (TARGET_SHA or the then-current `main`)
and passes after the repair. The tracker row changes in a separate PR after the fix
(`repo-change-protocol` §9).

1. **Fail closed when the master key is missing but a database exists (D-007, F-9
   residual).**
   - *Scope:* `MasterKeyProvider` and `ArciumApp` startup on Android. When
     `master_key.blob` is absent and `arcium.db` exists, do not generate a new key. Surface
     a distinct, non-onboarding state. No recovery or reset flow, no change to key
     derivation or the storage format.
   - *Prerequisites:* an owner decision on what the user sees (error screen only).
     Security review (key lifecycle, durable identity).
   - *Acceptance:* an instrumentation test creates a store and an identity, deletes the
     blob, restarts the provider and app start-up, and asserts no onboarding and no second
     identity row. On the baseline it reaches onboarding or creates a second row, as the
     Rust probe above shows. After the fix it passes. The first-run path, with no blob and
     no database, still creates a key.
2. **Make the license step fail on an sdkmanager failure (D-011, A-4).**
   - *Scope:* `android-ci.yml:32` and `android-two-device-e2e.yml:90` only. Replace
     `|| true` with the `PIPESTATUS[1]` pattern of `native-artifact-baseline.yml:38-42`.
   - *Prerequisites:* an owner task that permits a workflow change. It is a CI-integrity
     change, so it gets security review.
   - *Acceptance:*
     - the pipeline shape the PR introduces, run with a fake `sdkmanager` that exits 1,
       fails the step on both files; the baseline form exits 0;
     - with a fake that exits 0 under `pipefail`, it passes; the bare `pipefail` form
       exits 141;
     - both workflows are green on the PR head.
3. **Bound Tor bootstrap (D-008).**
   - *Scope:* `TorTransport::new` returns a `Bootstrap` error within a fixed bound instead
     of waiting indefinitely. `state_dir` handling (F-15(b)) is a separate item.
   - *Prerequisites:* do it together with, or before, the first production caller. The
     bound is an owner choice.
   - *Acceptance:* with no reachable Tor network, a non-ignored test completes with
     `Err(TransportError::Bootstrap(_))` inside the bound. On the baseline the same test
     does not return within 120 s (this pass: killed after about 99 s of running).
4. **Rollback-resistance design decision (D-009, F-10).** Design only; no implementation
   in this task.
   - *Scope:* a written decision on which of the following, if any, the store must resist,
     and against which attacker:
     - single-record rollback within one file;
     - whole-file rollback;
     - and whether a single-record rollback of ratchet or outbox state is exploitable.

     Crash consistency is already specified and stays out of scope. Choosing a witness or
     another external trust mechanism is part of the decision, not of this tracker.
   - *Prerequisites:* the `mbr-integration` skill's evidence and an owner decision.
   - *Acceptance:* the decision is recorded in `docs/S2-B2-DURABLE-MESSAGING.md` §8. Any
     later fix PR adds the three probes above as tests: the two rollback probes fail after
     the fix where the decision requires it, and the cross-record probe keeps passing.
5. **Decide the canonical contact-hash input (D-010, N-3).** A decision, not a fix.
   - *Scope:* the input form both clients must produce before calling `hash_contact`.
   - *Prerequisites:* an owner decision before the first production caller. It is a
     protocol change: both clients must apply it identically.
   - *Acceptance:* the decision is recorded next to the canonical standard. A shared vector
     set (raw input → normalized input → u64) passes in Rust and in TS. The existing vector
     `+1234567890` → `5364562789390625858` is unchanged.

---

## Update 2026-11-06: master-key loss at start-up (PR #133)

**Snapshot:** `main` @ `090bb17b38c80ab0cf66a8de9ed22f0d92034336`, the merge commit of PR #133. Its parents are `7455da8` and the PR head `53409be`, and its tree `5e523cc` equals the PR head tree. This section updates one residual of **F-9**: the master-key-lifecycle path that the F-9 row's scope note called *unresolved*. The continuity record tracks the same path as lead D-007. F-9's status and its scoped FIXED meaning from PR #120 are unchanged. Everything below is about Android start-up.

### What the merged code does (SOURCE_VERIFIED at `090bb17`)

- **A key is created only on a first run.** `MasterKeyProvider.load(dir, store, alias)` (`android/app/src/main/kotlin/com/arcium/messenger/security/MasterKeyProvider.kt:76`) creates a key only when neither `master_key.blob` nor the store exists (`:78-80`). The store counts as present if `arcium.db` or `arcium.db-journal` exists (`:111-112`). This check runs before any Keystore access.
- **A missing blob with an existing store is reported, and nothing is created.** It returns `MissingForExistingStore` (`:79`). No wrapping key, blob or temporary blob is written.
- **An existing blob is never replaced.** The wrapping key is only looked up, never created (`:82-88`). If the Keystore cannot be read, the alias is missing, the blob is malformed or GCM fails, the result is `Unavailable(reason)` (`:85`, `:88`, `:92`). The reason holds an exception class name, never key material. The existing blob and store are left as they are.
- **Start-up is gated.**
  - `ArciumApp.onCreate` runs the check through `AppStartup` (`ArciumApp.kt:19-20`, `startup/AppStartup.kt:50`).
  - `StoreStartup.open` turns both results into a blocked start-up (`startup/StoreStartup.kt:29-30`) and zeroes the key after the open (`:40`).
  - `core` and `messenger` are set only once start-up is `Ready` (`ArciumApp.kt:33-34`).
  - `MainActivity` composes the navigation, and with it every ViewModel, only behind `StartupGate`. It starts the visible-sync loop only after `Ready` (`MainActivity.kt:26`, `:32`).
  - `StartupGate` shows an error screen with **Try again**, which runs the same check (`ui/startup/StartupGate.kt:42-44`).
  - Retries are serialized, and initialization happens once (`AppStartup.kt:50-52`). A check that throws blocks start-up instead of crashing (`:56`).
- **No reset, deletion or recovery flow exists.** The cryptography, protocol and storage format are unchanged.

### Runtime evidence

- **Baseline counterexamples** (RUNTIME_VERIFIED, on unfixed code, API 30 x86_64 emulator):
  - Android Instrumentation run 42240380410, on `a2a8df2` = `7455da8` plus one test: `startup created a replacement master key for an existing store: blobRecreated=true, identityState=Absent, startDestination=onboarding, onboardingCreatedSecondIdentity=true`.
  - Full-process two-device run 42253845506, on branch `test/d007-restart-baseline` @ `d282620` = `7455da8` plus test files only:
    - cold start with the blob deleted: onboarding was shown, the messenger started, a replacement blob was written;
    - cold start with a garbage blob: the process crashed with `IllegalStateException: unrecognized master key blob`.
- **On the merge commit `090bb17`** (RUNTIME_VERIFIED; push runs, all success):
  - Arcium CI 42275239981.
  - Android CI 42275239858.
  - Android Instrumentation 42275239778, job `connected-tests`. Its "Require executed, unskipped tests" step fails on any failed, errored or skipped test. The per-test count of this run was not read here. On the PR head the same suite reported `tests=37 failures=0` (run 42242885623).
  - Android two-device run 42275239864: `E2E steps=17 passed=17 failed=0`. Its step 9, `android/e2e/master_key_restart.py`, ran five cold starts of the real app process on an emulator verified by `android/e2e/emulator_guard.py`, and logged `MASTER-KEY RESTART steps=5 failures=0`:
    - blob deleted: `screen=startupBlocked`, `messengerStarted=false`, three retries still blocked, no blob or temp blob written, `arcium.db` SHA-256 unchanged before and after;
    - garbage blob: blocked through three retries, no crash, the blob and the store unchanged byte for byte;
    - first launch, intact restart, and restart after restoring the blob: the same identity, no onboarding.
- **Tests on `main`:**
  - `security/MasterKeyLossInstrumentationTest`;
  - `security/MasterKeyProviderInstrumentationTest`, with its own Keystore alias and directory: missing blob, empty store or journal only, malformed blob, tampered blob, deleted wrapping key;
  - `startup/StoreStartupInstrumentationTest`;
  - `ui/StartupGateInstrumentationTest`;
  - JVM `startup/AppStartupTest`;
  - `e2e/MasterKeyRestartTest`, driven by `android/e2e/master_key_restart.py`, with `android/e2e/test_emulator_guard.py` as the fake-adb guard check.
- A green run shows that these tests passed on an API 30 emulator. It is not proof that start-up is secure in general.

### What is fixed, and what stays open

- **Fixed — merged (PR #133, `090bb17`), scoped as follows:** on Android start-up, an existing store whose `master_key.blob` is missing, corrupted or unusable no longer gets a replacement key. It never reaches onboarding or a second identity, the app does not crash, and the existing blob and store are not changed.
- **Not established, or still open:**
  - **The Rust layer is unchanged.** A different master key that reaches `ArciumCore` by some other path still reads as "no identity" (`Ok(None)`), as the F-9 scope states. Only the Android start-up path above is closed.
  - **A deleted store with an intact blob** opens a new, empty store under the existing key. The data is already gone in that case; nothing recovers it.
  - **There is no recovery flow.** The user stays on the error screen until the original blob and key are available again.
  - **Backup, restore and device transfer were not tested.** `allowBackup="false"` alone does not rule them out. A restored blob without its Keystore key takes the `Unavailable` path, INFERRED from source.
  - **The deleted-wrapping-key case** was exercised only in-process, with a test alias, not with a cold start of the real app.
  - **Physical devices and Android versions other than API 30** are NOT_VERIFIED.
  - **The JVM `AppStartupTest` has no per-class line** in the Android CI log, so its execution is NOT_VERIFIED.
  - **The full-process test runs only inside the two-device workflow**, after its messaging scenario.
  - **Two processes racing on a first run** (the debug-only `:victim` provider) could each write a blob. This predates PR #133.

---

## Update 2026-11-12 (`main` @ `a4a8479`)

**Snapshot:** `main` @ `a4a847914cc4d65042e80e024872abe880f55de9`, the merge commit of
PR #141. This section adds rows and changes no row above it; every row above keeps its own
snapshot. Each `path:line` below was re-read at `a4a8479`. Labels: `SV`
SOURCE_VERIFIED, `RV` RUNTIME_VERIFIED, `INF` INFERRED, `NV` NOT_VERIFIED.

**Where the D-numbers come from.** D-007 … D-011 are the agent's lead records of
2026-10-19 on the `continuity` branch (`decisions.md`). They are leads, not tracker IDs;
PR #132 (open) proposes homes for them in this file. Only D-008 and D-010 are recorded
here, because their fixes have merged.

**Runtime evidence for this section**, run locally at `a4a8479` on 2026-11-12:
`cargo test -p core-transport bootstrap_within` (3 passed);
`cargo test -p core-crypto contact_hash` (4 passed, including `shared_e164_vectors`);
`npx mocha --require ts-node/register src/crypto.test.ts` in `arcium-psi/tests`
(18 passing, including "canonical E.164 input matches the shared vectors (D-010)").
The R-rows rest on probes run at `fe7f3b5` on 2026-11-09/10 (synthetic data, a local
relay, a debug build, probes not committed). PR #141, merged between `fe7f3b5` and
`a4a8479`, changed dependencies, `vendor/` and CI only (`git diff --stat fe7f3b5 a4a8479`),
so the probed code paths are the same; the probes were not re-run at `a4a8479` (`INF`).

### D-008 and D-010: fixed or decided

| ID | Item | Status | Evidence (`main` @ `a4a8479`) |
|----|------|--------|-------------------------------|
| **D-008** | `TorTransport::new` had no bootstrap bound: arti keeps retrying its directory download, so an unreachable Tor network made `new` wait for hours. | **FIXED — merged** in PR #137 (merge commit `04968d3`). Scope: the bootstrap only. | `BOOTSTRAP_TIMEOUT` = 120 s (`crates/core-transport/src/lib.rs:15`); `new` calls `new_within` with it (`:35-37`); `bootstrap_within` wraps the bootstrap in `tokio::time::timeout` and maps a timeout to `TransportError::Bootstrap` (`:59-71`). Tests `bootstrap_within_times_out_on_a_bootstrap_that_never_finishes`, `…_reports_a_bootstrap_error_as_bootstrap`, `…_returns_a_finished_bootstrap` pass (`RV`). **Not changed:** `state_dir` is still ignored (`_state_dir`, `:40`), so **F-15(b) stays open**; the transport is still not called by the app (`ArciumCore.kt:263-269`, F-15). `new_fails_gracefully_without_tor` stays `#[ignore]` (`:166`) and was not run here (`NV`). *(Note 2026-11-24: arti is 0.48 since PR #262; the bound, `new` and `bootstrap_within` are at the lines cited, and the test is now at `:192-193`; see "Update 2026-11-24: arti 0.48 in core-transport".)* *(Note 2026-11-24: since PR #265 `state_dir` is used, so F-15(b) is fixed, and the lines cited moved; see "Update 2026-11-24: Tor connector in core-transport".)* *(Note 2026-11-28: `ArciumCore.kt:263-269` was the Kotlin `startTorTransport`, removed by PR #276; since PR #275 the app's core calls the Tor transport for a relay at an onion address (see "Update 2026-11-27: Tor for onion relays"); see "Update 2026-11-28: Tor route in Settings and core fixes".)* |
| **D-010** | No phone-number normalization before `hash_contact`: formatting variants of one number hashed differently. | **DECIDED and implemented — merged** in PR #139 (merge commit `fe7f3b5`). **No production caller yet.** | Strict E.164 input: `normalize_e164` (`crates/core-crypto/src/contact_hash.rs:60`) accepts `+` then 2–15 ASCII digits with a non-zero first digit after removing listed separators, and refuses anything else (doc `:6-12`); `hash_contact_e164` hashes only the canonical form (`:74-75`); `hash_contact` itself is unchanged (`:47`), so the canonical hash rule in `CLAUDE.md` still holds. TS twin `normalizeE164` (`arcium-psi/tests/src/utils.ts:20`). Both sides check the same vector file `crates/core-crypto/tests/contact_hash_e164.tsv` (Rust test `shared_e164_vectors`, `contact_hash.rs:86`; TS `crypto.test.ts:62-72`) (`RV`). No caller outside tests: the only other mentions are comments (`crates/mobile-ffi/src/lib.rs:193`, `crates/core-crypto/src/session_handle.rs:9`, `MessageRepository.kt:57`) (`SV`). National-format input (no `+`) is refused, not guessed; a caller must format it as E.164 first. |

### R-series: architecture review of 2026-11-10 (open)

Found in the architecture review at `main` @ `fe7f3b5`. A fix for any of them needs its own
owner task; R-1, R-4, R-5 and R-6 need a design decision first. Severity is the reviewer's
estimate. (The review's own letters are kept in brackets; its finding B, the red
`cargo audit`, is closed by PR #141 and has no row.)

| ID | Sev | Item | Status | Evidence (`main` @ `a4a8479`) | Label |
|----|-----|------|--------|-------------------------------|-------|
| **R-1** (A) | MED | **Second first contact to an offline recipient is refused; one key order dead-ends.** Trigger: Bob is offline; Alice and Carol both write to him for the first time. His bundle holds one one-time prekey, and both handshakes name it. Consequence: Bob accepts Alice's first message, which consumes and replaces the prekey; Carol's handshake is refused on every round. Carol's text stays "sent to relay" for good. Neither side can restart: removal is refused while a text is pending. If Bob then writes to Carol, the two get a session conflict. When Carol's key is the greater, a manual resolve recovers and her first text is marked not delivered. When Bob's key is the greater, both sides are stuck: Bob waits for Carol's handshake, which is always refused, and `resolve_session_conflict` refuses both. | **OPEN** — needs a protocol decision | Refusal: `check_answerable` (`crates/mobile-ffi/src/lib.rs:885-900`), `OneTimePrekeyUnavailable` at `:894-896`; consume and replace at `:940-944`; the network layer flags `HANDSHAKE_REFUSED` and reports "handshake refused" (`crates/mobile-ffi/src/network.rs:638-649`). Removal refused with a pending text: `PendingOutgoing` (`crates/core-protocol/src/messaging/removal.rs:78-81`). Resolve refusals: `crates/mobile-ffi/src/network/chat.rs:536-545`. The refusal of a second initiator is documented (`docs/NET-MESSAGING.md:259-268`); how often it happens and the dead end are not. | `RV` at `fe7f3b5` (two-key-order probe); `SV` at `a4a8479` |
| **R-2** (C) | MED | **An unknown COMMIT outcome stalled the exchange for every contact.** Trigger: a COMMIT whose outcome is unknown (reproduced with `SQLITE_BUSY`) leaves a session unresolved. Consequence: `recover_session` runs only when a message is received on that session, but the round sends first, and a send on the unresolved session fails the whole round. No contact sends or receives until the app restarts; the envelopes stay on the relay. | **OPEN — fix in review** (PR #140, not merged) | Recovery only on the receive path: `crates/mobile-ffi/src/network.rs:651-652`; the error `SessionUnresolved` (`crates/mobile-ffi/src/lib.rs:98-99`); the contract that the network layer recovers (`docs/NET-MESSAGING.md:251`). Probe at `fe7f3b5`: six rounds with `fetched=0`, two envelopes left on the relay, everything delivered after a manual `recover_session`. PR #140's regression test fails on the base and passes with the fix. | `RV` at `fe7f3b5`; `SV` at `a4a8479` |
| **R-3** (D) | LOW | **Cost grows linearly with history length.** Every send, every sync round and every conversation-list refresh reads and decrypts the whole history of a conversation; listing entries is a full prefix scan of the table. There is no paged read in the API or the UI. Measured (debug build, server): idle round 87 ms at 50 messages, 498 ms at 500. A round runs every 1.5–4 s. | **OPEN** — needs a design decision (paging, index) | `entries` (`crates/mobile-ffi/src/network/chat.rs:727`), called per send (`:423`), per conversation (`:556`) and per round (`:867`); `list_keys_with_prefix` scans with `substr(k, …)` (`crates/core-storage/src/lib.rs:241-247`). | `RV` (debug, up to 500 entries, at `fe7f3b5`); phone `NV` |
| **R-4** (E) | LOW | **No time bound on a relay operation or a sync round.** `timeout_ms` is a per-syscall socket timeout, not a per-operation bound, while the doc comment promises one. A relay that trickles bytes keeps a round running indefinitely: with `timeout_ms = 300` and 1 byte per 100 ms, sync had not returned after 20 s; one 1 MiB frame would take about 29 hours. Sync runs on one thread, so changing the relay in settings does not help until a restart. | **OPEN** — needs limits chosen | `set_read_timeout` / `set_write_timeout` (`crates/relay/src/client.rs:45-46`); doc "Every network operation times out after `timeout_ms`" (`crates/mobile-ffi/src/network.rs:155`); one sync thread (`MessengerService.kt:76`). | `RV` (trickle probe at `fe7f3b5`); single-thread consequence `INF` |
| **R-5** (F) | LOW | **Retransmission without backoff.** Every unacknowledged message or handshake is sent again every 5 s while the app is open, with no limit and no backoff, including the refused handshake of R-1. Traffic and battery cost not measured. | **OPEN** — needs limits chosen | `due` compares against a fixed `retransmit_after` (`crates/mobile-ffi/src/network.rs:486-490`); default `retransmitAfterMs = 5_000u` (`android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt:297`). | `SV`; cost `NV` |
| **R-6** (G) | LOW | **The signed prekey is never rotated.** Prekeys are created once, when none exist, and the signed prekey then stays for the life of the identity. Only the one-time prekey rotates. | **ACCEPTED (Owner decision 2026-11-12)** — not rotated for now; revisit together with X-6. Reason: every handshake on `main` uses a one-time prekey, whose secret is deleted on use (`crates/mobile-ffi/src/lib.rs:940-944`), so a later leak of the signed-prekey secret does not open past first messages; and that secret lives in the same encrypted store as the identity and every session, so a leak of it is a leak of all of them. Rotation without a grace period would rely on the handshake refusal of PR #144 (not merged) to restart first contacts in flight. | `put_bundle` calls `establish_prekeys` only when `PREKEYS_KEY` is absent (`crates/mobile-ffi/src/network.rs:323-340`); the only other production call is in the unused `MessageRepository` (`MessageRepository.kt:113`). | `SV` |
| **R-7** (H) | INFO | **Stubs and stale descriptions.** (a) `MessageRepository` is not used by the app and its "No transport" section is stale (`NetworkMessenger` exists). (b) The manifest requests Bluetooth permissions for the BLE stub. (c) `repo-map.md` does not list the `relay` crate. (d) `ChatViewModel` does not clear its error after a successful reload. | **OPEN** — text fixes are task T4; deletions and the permission change are owner decisions | (a) `android/app/src/main/kotlin/com/arcium/messenger/data/MessageRepository.kt:88`; (b) `android/app/src/main/AndroidManifest.xml:7-13`; (c) no `relay` in `.claude/skills/engineering-code-review/references/repo-map.md`; (d) `reload` sets `error` only in its `catch` and never clears it (`android/app/src/main/kotlin/com/arcium/messenger/ui/chat/ChatViewModel.kt:66-77`); it is cleared only when a send starts (`:98`). | `SV` |

### X-5 and X-6: carried over from PR #82

PR #82 (closed unmerged on 2026-11-11) proposed these two rows as X-4 and X-5. They are
renumbered here because PR #132 (open) uses X-4 for a different item. Both were re-checked
at `a4a8479`; the code has changed since #82 was written, so the anchors are new.

| ID | Item | Status | Evidence (`main` @ `a4a8479`) | Label |
|----|------|--------|-------------------------------|-------|
| **X-5** | The responder used to read its prekey record under a store guard that was a temporary in an expression chain, so the guard was dropped at the end of the statement and X3DH ran unlocked. Any single-use prekey scheme built on that shape would let two concurrent handshakes consume the same one-time prekey. | **FIXED** (PR #81, `99c9f49`; the shape has changed again since) | `accept_first_message` takes `store: &mut EncryptedStore` (`crates/mobile-ffi/src/lib.rs:910-917`), so its caller holds the store for the whole read → check → rotate → write; the rotated record is written only if it is still byte-identical to the one read (doc `:902-909`). Concurrent handshakes were not exercised here. | `SV`; concurrency `NV` |
| **X-6** | **Residual replay on the SPK-only path.** The handshake format keeps a form without a one-time prekey, and the responder accepts it when it holds none. On that path nothing stops an exact replay: the root key re-derives identically and a recorded first message decrypts again. | **OPEN — currently unreachable** | Accepted when neither side has a one-time prekey: `(None, None) => Ok(())` (`crates/mobile-ffi/src/lib.rs:898`). No production writer makes a record without one: `establish_prekeys` always sets `opk: Some(…)` (`:683-697`), and the responder replaces a consumed one (`:940-944`). The residual becomes live as soon as anything produces a record without a one-time prekey, such as an exhaustion policy, or several one-time prekeys as considered for R-1. It must be closed together with such a change. | `SV` |

---

## Update 2026-11-13 (`main` @ `c2c967c`)

**Snapshot:** `main` @ `c2c967c3fc8f63d931dcdd4f46d35db72e02113b`, the merge commit of
PR #126. This section adds rows and records new statuses for rows above; it edits no row
above, so every row above keeps its own snapshot, and where a row above and a row here
disagree, the row here is the later one. Each `path:line` below was re-read at `c2c967c`.
Labels: `SV` SOURCE_VERIFIED, `RV` RUNTIME_VERIFIED, `INF` INFERRED, `NV` NOT_VERIFIED.

**Runtime evidence for this section.** `cargo test --workspace --locked` at `c2c967c`:
exit 0, 489 passed, 0 failed, 4 ignored. Push CI on the merge commits named below: Arcium CI, success on
each (run IDs in the rows). Probes named below were run locally on 2026-11-12/13
(synthetic data, a local relay, a debug build) and were not committed. CI and the local
runs use emulators and a local relay only; no phone, no production relay (`NV`).

### Status of the R-series and of rows above

| ID | Status at `c2c967c` | Evidence (`main` @ `c2c967c`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-1** (first contact) | **FIXED — merged** in PR #144 (merge `51a5f09`, Arcium CI run 43360735485). Owner decisions D1–D3, D1 revised by M1–M4: the responder sends `HANDSHAKE_REFUSAL_V1` and the initiator restarts. The refusal is authenticated by a MAC, not a signature (review finding F-144-1: a signature made an elicited refusal a transferable proof that the refuser has the initiator pinned). | Object and checks: `HANDSHAKE_REFUSAL_V1_LEN` (`crates/mobile-ffi/src/lib.rs:616`), `HandshakeRefusal::open` (`:674`), `make_handshake_refusal` (`:1150`), `open_handshake_refusal` (`:1178`). Tag: `refusal_tag` / `verify_refusal_tag` (`crates/core-crypto/src/refusal_mac.rs:80`, `:100`), info `"arcium/handshake-refusal-mac/v1" \|\| refuser \|\| initiator` (`:45`), low-order keys refused (`:62`). Queue, send and check: `queue_refusal`, `send_refusals`, `take_refusal` (`crates/mobile-ffi/src/network.rs:1013`, `:1051`, `:1111`); restart `restart_after_refusal` (`crates/mobile-ffi/src/network/chat.rs:460`). Tests: 11 in `tests::first_contact`, 4 in `core_crypto::refusal_mac` (one a byte-for-byte vector computed independently with Python `cryptography`). The F-144-2 fix (refusals not lost on a relay refusal or a broken SEND) is in the same merge. **Remaining:** key-compromise impersonation of refusals by whoever holds the initiator's own identity secret (documented, `docs/NET-MESSAGING.md` section 8); a refusal queued but not yet stored is lost if the responder's process ends; with k > 3 contenders the k-th may wait about 10 minutes per further refusal (D3). The static-DH MAC has not been reviewed by a cryptographer: **REVISIT AT SECURITY AUDIT.** | `SV`, tests `RV`; review `INF` (independent model review, not a proof) |
| **R-2** (unresolved session) | **FIXED — merged** in PR #140 (merge `287d54c`, run 43346528115). | `sync_round` calls `recover_if_unresolved` for every contact before anything else (`crates/mobile-ffi/src/network.rs:561`; `crates/mobile-ffi/src/messaging_api.rs:217`). Tests `tests::unresolved` (the regression test fails on the old base). **Remaining:** if `recover_session` itself fails, the round still stops for every contact. | `SV`, `RV` |
| **R-3** (history cost) | **FIXED for rounds and pages — merged** in PR #146 (merge `f369b2b`, run 43327602632) and PR #149 (UI, merge `89256af`, run 43348033092). | Open-entry record `open_entries` / `open_seqs` (`crates/mobile-ffi/src/network/chat.rs:903`, `:917`); paged read `chat_entries_page`, at most `MAX_PAGE` = 200 (`:559`, `:38`); the screen loads a window of pages, `loadWindow` (`android/app/src/main/kotlin/com/arcium/messenger/ui/chat/ChatViewModel.kt:70`). Measured in a debug build on a server: idle round 14 ms at 50 entries and 74 ms at 5000 (was 96 ms at 50 and 608 ms at 500). **Remaining:** every namespace listing still scans the whole table (`list_keys_with_prefix`, `crates/core-storage/src/lib.rs:241-246`); the full `chat_entries` stays linear by design; cost on a phone `NV`. | `SV`, `RV` (debug, server) |
| **R-4** (no time bound) | **FIXED — merged** in PR #145 (merge `997c416`, run 43332361616). One relay request at most 30 s, one round at most 120 s of relay requests. | `REQUEST_DEADLINE` (`crates/relay/src/client.rs:35`), `ROUND_BUDGET` (`crates/mobile-ffi/src/network.rs:208`). A round cut by the budget reports `BUDGET_EXHAUSTED`, which is not a network error, and the next round continues where the passes stopped (`:243`, `Resume` `:154`) (review findings F-145-1 and F-145-2, fixed before the merge). **Remaining:** the DNS lookup in `Connection::connect` (`crates/relay/src/client.rs:87`) is not bounded; below about 35 KiB/s a full page cannot arrive within 30 s (no adaptive paging). *(Note 2026-11-24: since PR #264 that lookup is in `TcpConnector::connect`, the relay client's default connector; see "Update 2026-11-24: Tor connector in core-transport". Status unchanged.)* | `SV`, `RV` |
| **R-5** (no backoff) | **FIXED — merged** in PR #145. Retransmission waits `retransmit_after`, doubling with each send, capped at 5 minutes. | `due`, `retransmit_wait` (`crates/mobile-ffi/src/network.rs:743`, `:751`), `RETRANSMIT_CAP` (`:212`). Scaled test: 7 sends instead of 101 over 10 simulated minutes. Battery and traffic on a phone `NV`. | `SV`, `RV` |
| **R-6** (signed prekey not rotated) | **ACCEPTED** (unchanged). R-1's fix exists now, so rotation without a grace period could rely on refusals; the Owner's decision to revisit with X-6 stands. | — | — |
| **R-7** (stubs, stale text) | (a), (c) **FIXED — merged** in PR #143: `MessageRepository` says it is not the app's messaging path (`android/app/src/main/kotlin/com/arcium/messenger/data/MessageRepository.kt:88`); `repo-map.md` lists the `relay` crate (`.claude/skills/engineering-code-review/references/repo-map.md:66`). (d) **FIXED — merged** in PR #148 (merge `132d48c`, run 43354216240): a successful reload clears the read error, `afterReload` (`ChatViewModel.kt:52`). (b) **OPEN**: the manifest still requests Bluetooth permissions for the BLE stub (`android/app/src/main/AndroidManifest.xml:7-13`); an Owner decision. | as named | `SV` |
| **A-4** (D-011, `\|\| true` on the SDK-license step) | **FIXED — merged** in PR #135 (merge `9d9b002`). Only `sdkmanager`'s own status decides the step. | `.github/workflows/android-ci.yml:35-39`; `.github/workflows/android-two-device-e2e.yml:94-98`. Both workflows passed on the merge commit (Android CI run 43366662057, two-device run 43366662065). The `\|\| true` left in the two-device workflow guard diagnostic log dumps only (`:119`, `:145`, `:147-148`). | `SV`, `RV` |
| **D-009** (single-record rollback) | **DECIDED** — the Owner's decision is recorded in `docs/S2-B2-DURABLE-MESSAGING.md` section "Rollback decision (D-009, 2026-11-08)" (PR #138). The F-10 scope is unchanged. | `docs/S2-B2-DURABLE-MESSAGING.md:360` | `SV` |
| **X-5** | **FIXED** (unchanged); the anchor moved: `accept_first_message` (`crates/mobile-ffi/src/lib.rs:1028`), byte-identical replace (`:1026`, `:1085`). | as named | `SV` |
| **X-6** | **OPEN — still unreachable.** PR #144 added no SPK-only acceptance and no record without a one-time prekey. | `(None, None) => Ok(())` (`crates/mobile-ffi/src/lib.rs:1016`); `establish_prekeys` always sets one (`:801`, `:814`). | `SV` |

### New rows

Found in the adversarial review of PR #144–#147 on 2026-11-12 and later this week.

| ID | Sev | Item | Status | Evidence (`main` @ `c2c967c`) | Label |
|----|-----|------|--------|-------------------------------|-------|
| **R-8** | MED | **One contact's full mailbox stopped every round.** The first relay refusal of a SEND ended the round before the device's own mailbox was read, so filling one contact's mailbox (the relay has no sender authentication) stopped sending and receiving for every contact. | **FIXED — merged** in PR #151 (merge `96bb487`, run 43344190502). A refused recipient waits, the round goes on for everyone else, and the report line does not start with `network:`. | `send_to`, `held`, `publish_pending` (`crates/mobile-ffi/src/network.rs:785`, `:766`, `:812`). Tests `tests::send_refusal` (all three fail on the old base). **Remaining:** delivery to the full mailbox's owner stays blocked until it has room; closing that needs relay authentication. | `SV`, `RV` |
| **R-9** | LOW | **A reader of a mailbox learns whom its owner has pinned.** A message "from X" that its owner cannot yet decrypt stays in the mailbox when X is a pinned contact without a session and is deleted when X is a stranger; a refusal answers a forged handshake only when X is pinned. Anyone can read a mailbox on the development relay. The refusal is no longer a proof of it (R-1), but the yes/no answer remains. | **OPEN** — needs relay authentication; a protocol decision | Keep versus delete: a message from a pinned sender without a session is kept (`NoSession` → `Fate::Keep`, `crates/mobile-ffi/src/network.rs:973`), one from a stranger is dropped (`:880`); refusals go only to pinned senders (`queue_refusal`, `:1013`). Documented in `docs/NET-MESSAGING.md` section 8. | `RV` (probe at `0231352`, not committed); `SV` |
| **R-10** | LOW | **A missing history entry now fails more.** History paging and the open-entry record assume entries numbered without gaps (true for every version of `chat.rs`). A missing entry, which only a damaged store can produce, makes `chat_entries_page` fail, and makes the one-time build of the open-entry record fail, so `sync_conversations` fails for every contact until it is fixed. | **OPEN** — optional hardening: skip missing numbers in the build | `entries_in` and the build in `open_seqs` read every number with `?` (`crates/mobile-ffi/src/network/chat.rs:892-896`, `:931-936`). | `RV` (probe on PR #146's head, not committed); `SV` at `c2c967c` |
| **R-11** | LOW | **Relay descriptor leak.** The development relay kept a descriptor per connection after the connection ended, and an accept error spun the accept loop. | **FIXED — merged** in PR #147 (merge `c7ad480`, run 43306682803). | Connections tracked in a map (`crates/relay/src/server.rs:85`, `:175`) and removed when they end (`:183`), `stop` closes the rest (`:117-120`); `ACCEPT_RETRY` pause (`:166`). | `SV`, `RV` |
| **R-12** | LOW | **A replayed receipt is answered, though the document says it changes nothing.** `docs/NET-MESSAGING.md` section 5 says "a replayed receipt is a duplicate and changes nothing" (`:193-194`). In the code every duplicate, of any kind, is answered with a receipt (`receipt_again`). For a replayed RECEIPT that answer is a "receipt of a receipt", which the peer accepts (one ratchet step on each side) and ignores. It is sent for the first replay, then at most once per minute per replayed message. The answer also shows whoever replays an envelope that the device is online and still holds the session. Raised in PR #126 as an open question. | **OPEN** at `c2c967c` — Owner decision: change the document, or answer only duplicates that were answered the first time. *(2026-11-13, `main` @ `c07bf36`: the Owner chose the code change; **FIXED — merged** in PR #154. See "Update 2026-11-13: R-12 fixed" below.)* | `Received::Duplicate` → `receipt_again` (`crates/mobile-ffi/src/network.rs:968`, `:1215`). Probe at `c2c967c` (not committed): three replays of one receipt gave one, one and zero answers; starting from settled devices, the peer accepted each answer and published nothing in reply. | `RV` (probe); `SV` |

---

## Update 2026-11-13: R-12 fixed (`main` @ `c07bf36`)

**Snapshot:** `main` @ `c07bf36636e1c8fbf29a5d4f693cff232196183f`, the merge commit of
PR #154. Only R-12 changes; every other row keeps the snapshot it cites. Each `path:line`
below was re-read at `c07bf36`. Labels as in "Update 2026-11-13" above.

**Runtime evidence.** At `c07bf36`, `cargo test --workspace --locked`: exit 0, 491 passed,
0 failed, 4 ignored; `cargo clippy --workspace --locked --all-targets -- -D warnings`: exit 0.
Both new tests were re-run on 2026-11-13 against the merged code with one part of the fix put
back. The replay test fails with `network.rs` of `c2c967c` (`published: 1`). The crash test
fails with only the old `mark_read` (`Transmitted`, not `Delivered`). Both pass at `c07bf36`. Push CI on `c07bf36`: success on
all four workflows (Arcium CI run 43514569716, Android Native Bridge 43514569876, Android
Instrumentation 43514569691, two-device messaging 43514569662). CI and the local runs use
emulators and a local relay only; no phone, no production relay (`NV`).

| ID | Status at `c07bf36` | Evidence (`main` @ `c07bf36`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-12** (replayed receipt answered) | **FIXED — merged** in PR #154 (merge `c07bf36`). The Owner chose to change the code so that `docs/NET-MESSAGING.md` section 5 holds. A duplicate is now answered only if the original was: a text or an OPEN, whose receipt was committed when it was accepted. A replayed receipt, or a duplicate of a payload this build does not know, gets no answer. `mark_read` first commits a text's receipt if it is missing. That closes the crash window the first change opened: a text accepted, then the process killed before its receipt was committed, then marked read before any sync round. | The `Duplicate` arm calls `receipt_again` (`crates/mobile-ffi/src/network.rs:987-989`). `receipt_again` answers only when `prior_send` finds the receipt `client_id::receipt(id, 0)` (`:1242`, `:1244`). Send-id records are never deleted (`crates/core-protocol/src/messaging/removal.rs:49`). `mark_read` (`network.rs:433`, `:438-445`). Specification: `docs/NET-MESSAGING.md:199-202`. Tests: `tests::network::a_replayed_receipt_is_not_answered` (`crates/mobile-ffi/src/tests/network.rs:442`; fails with `network.rs` of `c2c967c`: `published: 1`); `tests::network_crash::a_recipient_killed_before_its_receipt_still_confirms_the_text` (`crates/mobile-ffi/src/tests/network_crash.rs:226`; fails with the old `mark_read`: the text stays `Transmitted`); the unchanged `a_lost_receipt_is_answered_again_when_the_text_is_repeated` (`tests/network.rs:481`). **Remaining:** a replayed text or OPEN is still answered, by design, since its sender may have lost the receipt: at most once per message per minute. Whoever replays one still learns that the device is online (`INF`). A receipt abandoned by `resolve_session_conflict` counts as answered: no new receipt, as before the change. Phones and a production relay `NV`. | `SV`, tests `RV` |

---

## Update 2026-11-14 (`main` @ `de328a1`)

**Snapshot:** `main` @ `de328a1b910dcad482775e153d3a8179eabeb10e`, the merge commit of
PR #156. This section adds rows and notes; it edits no row above. Each `path:line` below was
re-read at `de328a1`. Labels: `SV` SOURCE_VERIFIED, `RV` RUNTIME_VERIFIED, `INF` INFERRED,
`NV` NOT_VERIFIED.

**Runtime evidence for this section.** `cargo test --workspace --locked` at `de328a1`
(2026-11-13): exit 0, 491 passed, 0 failed, 4 ignored. R-13 and R-14 rest on two temporary
tests (`probe_forged_conflict_then_resolve`, `probe_many_lost_receipts`) added to
`crates/mobile-ffi/src/tests/chat.rs` in a disposable clone of `de328a1` and run once with
`cargo test -p mobile-ffi --locked probe_ -- --nocapture --test-threads=1` (2 passed,
1307 s; debug build, a local relay from `net_harness`, synthetic data). They were not
committed. No phone and no production relay (`NV`). The other rows come from reading source.

### Notes on rows above

| ID | Note at `de328a1` |
|----|-------------------|
| **R-7 (b)** | Still **OPEN**. Fix in review: PR #157 (removes the Bluetooth permissions and the unused BLE, Solana and PSI-discovery stubs; not merged). |
| **R-10** | Still **OPEN**. Fix in review: PR #158 (a missing history number is skipped by the record build, pages and the summary; not merged). |

### New rows

| ID | Sev | Item | Status | Evidence (`main` @ `de328a1`) | Label |
|----|-----|------|--------|-------------------------------|-------|
| **R-13** | HIGH (needs the user to resolve the conflict) | **A false session conflict dead-ends the conversation.** Trigger: Alice, whose identity key is the greater one, starts a session with Bob while Bob is offline. Anyone who can write to Alice's mailbox stores an 84-byte handshake naming Bob. It is built from public bytes only, and today anyone who reaches the relay can do this. Alice's device flags a conflict, and her user resolves it, which removes Alice's session and sets accept-only. Bob then comes online and accepts Alice's original handshake and first message, so he holds an established session. Consequence: Alice waits for a handshake from Bob that never comes. Bob's messages stay undecrypted in her mailbox. Her first text shows `NotDelivered` although Bob received it, her later texts stay `Queued`, and Bob's texts stay `Transmitted`. Restarting either device does not help, and a second resolve is refused on both sides. With the keys the other way round the conflict clears by itself once Bob confirms the session, because only the greater key may resolve. `docs/NET-MESSAGING.md` section 10 said resolving a false conflict "only delays the conversation"; corrected in this PR. | **OPEN**: needs a design decision; options in PR #159 (`docs/SESSION-RECOVERY-OPTIONS.md`) | Conflict flagged for any handshake from a peer whose session here is an unconfirmed start of our own: `crates/mobile-ffi/src/network.rs:921-931`. Resolve removes the session and sets accept-only: `crates/mobile-ffi/src/network/chat.rs:675-696`. An accept-only device never starts a session (`:778`); only a confirmed session clears the flag (`:768-773`). A message without a session is kept: `network.rs:992`. Bob's established session cannot be removed: `crates/core-protocol/src/messaging/removal.rs:75-77`. Probe `probe_forged_conflict_then_resolve`: the final states above; unchanged after both devices restart; `resolve_session_conflict` refused on both with "no session conflict with this contact". | `RV` (probe); `SV` |
| **R-14** | HIGH (on this skill's scale: a remote party permanently desynchronises one direction; needs more than 1000 consecutive losses) | **More than `MAX_SKIP` lost messages in one sending chain stop that direction for good.** A receipt is a ratchet message, and it leaves the outbox as soon as the relay accepts it. If the relay then loses it (it keeps mailboxes in memory, so a restart is enough) or anyone deletes it (DELETE is unauthenticated, R-9), that chain position is gone. A few losses only delay delivery: the text is sent again and gets a new receipt. But once more than 1000 consecutive messages of one sending chain are lost, the receiver refuses every later message of that chain (`SkipLimit`, read as `Crypto`, dropped and deleted). The chain does not restart: the sender moves to a new chain only after receiving the peer's next ratchet key, and the peer sends that only in a message it can no longer get through. | **OPEN**: needs a design decision; options in PR #159 | `MAX_SKIP = 1000` (`crates/core-crypto/src/ratchet.rs:41`), the check (`:296-299`). A receipt leaves the outbox on relay acceptance (`crates/mobile-ffi/src/network.rs:881-883`). An undecryptable message is dropped (`:993-996`). Probe `probe_many_lost_receipts`, run in 1002 rounds: Alice sends a text, Bob syncs twice, and a third party deletes everything stored for Alice (3355 envelopes in all). Afterwards Alice dropped every message from Bob in each round (6 to 14 per round). Her texts stayed `Transmitted` and Bob's new text never arrived. After both devices restarted the same held (986 dropped in one round). | `RV` (probe); `SV` |
| **R-15** | LOW | **A text that is never acknowledged stays `Transmitted` for good.** It is sent again at most every 5 minutes for as long as the app is open, with no limit. There is no failed state: `NotDelivered` is reached only through a conflict resolution or a restart after a refusal. There is also no user action to give the text up. R-13 and R-14 are cases of this. | **OPEN**: needs a product decision (PR #159, section 4) | States (`crates/mobile-ffi/src/network/chat.rs:54-71`); `NotDelivered` set by `resolve_session_conflict` (`:675`) and `restart_after_refusal` (`:460`); `retransmit_wait`, capped at `RETRANSMIT_CAP` (`crates/mobile-ffi/src/network.rs:770-776`, `:212`); `abandon_outgoing` is `pub(crate)` and not exported (`crates/mobile-ffi/src/messaging_api.rs:320`). | `SV` |
| **R-16** | LOW | **A refusal lost after the relay stored it is not repeated until the responder restarts.** A responder refuses each refused handshake at most once per process. The initiator retransmits the same handshake, so a refusal the relay lost, or that someone deleted, leaves the initiator waiting in `AwaitingPeer` until the responder's process restarts. Its texts are pending, so the initiator cannot remove the session, and there is no conflict to resolve. `docs/NET-MESSAGING.md` section 6 states the code's rule. Section 8 said such a refusal is "sent again only after 10 minutes"; corrected in this PR. | **OPEN**: a liveness fix in the network layer (for example, refuse again once `REFUSAL_INTERVAL` has passed) | `sent_for` checked (`crates/mobile-ffi/src/network.rs:1046`) and recorded on a stored refusal (`:1103`); `REFUSAL_INTERVAL` (`:201`). That the initiator has no way out is read from `removal.rs:78-81` and `chat.rs:678-680`. | `SV`; no way out `INF`; not exercised (`NV`) |
| **R-17** | LOW | **Android shows "Connected" while rounds fail on the device.** The link state counts only report errors that start with `network:`. Any other error in a round's report leaves the banner at "Connected to the development relay" and is shown nowhere: a storage error such as R-10's, a refused handshake, a session error. | **OPEN**: an Android task | `reachedRelay` (`android/app/src/main/kotlin/com/arcium/messenger/messaging/MessengerService.kt:182`), used at `:165-171`; the banner (`android/app/src/main/kotlin/com/arcium/messenger/ui/contacts/ContactsScreen.kt:115`). | `SV` |
| **R-18** | INFO | **Android hardening not present.** (a) No `FLAG_SECURE`, so screenshots and the recent-apps preview show the chat. (b) The Keystore key that wraps the master key is created without StrongBox, unlocked-device or user-authentication requirements. (c) `allowBackup="false"` without `dataExtractionRules`, so device-to-device transfer on Android 12 and later is not excluded; this is already listed as untested in "Update 2026-11-06". Each item is a choice with costs: StrongBox is not on every device, and user authentication would block a future background sync. | **OPEN**: an Owner choice per item | (a) no `FLAG_SECURE` under `android/app/src/main`; (b) `KeyGenParameterSpec.Builder` (`android/app/src/main/kotlin/com/arcium/messenger/security/MasterKeyProvider.kt:150-157`); (c) `android/app/src/main/AndroidManifest.xml:17`, no `dataExtractionRules` attribute. | `SV`; device behaviour `NV` |
| **R-19** | INFO (pre-deploy; cost and rule conformance, no secrecy impact: the circuit is public) | **The PSI circuit is registered as on-chain, not off-chain.** `init_psi_intersect_comp_def` passes no circuit source (`None`), and the localnet test asserts that the stored source is `OnChain` and uploads the circuit into raw circuit accounts. The doc comments on the same instruction say OffChainCircuitSource with only the 32-byte hash on chain, and so does `CLAUDE.md` («OffChainCircuitSource»: "НИКОГДА не встраивай circuit в смарт-контракт"). A devnet deploy as the code stands would store the whole circuit on chain. Found while aligning `docs/HOME-DEPLOY.md` (PR #161). | **OPEN** — Owner decision before any deploy: switch to an off-chain source (URL plus hash) or restate the rule | `init_computation_def(&*ctx.accounts, None)` (`arcium-psi/programs/arcium-psi/src/lib.rs:42`) under comments claiming OffChainCircuitSource (`:37-38`, `:186`); the test expects `circuitSource.onChain` (`arcium-psi/tests/src/localnet/psi.localnet.ts:166-167`) and exercises `uploadCircuit` (`:181-188`). The `arcium-test` CI job runs that test (log not read for this row). | `SV`; CI `NV` |

---

## Update 2026-11-14: R-7 (b), R-10 and R-17 fixed (`main` @ `63b606d`)

**Snapshot:** `main` @ `63b606d2941b327c94e2635eaaf1f7ba9152a1d2`, the merge commit of
PR #163. Only the rows named here change; every other row keeps the snapshot it cites.
Each `path:line` below was re-read at `63b606d`. Labels as in "Update 2026-11-13".

**Runtime evidence.** At `0a8dbd4` (the merge of PR #160), `cargo test --workspace --locked`:
exit 0, 493 passed, 0 failed, 4 ignored; `cargo clippy --workspace --locked -- -D warnings`:
exit 0 (run locally on 2026-11-14). `0a8dbd4` → `63b606d` changes only files under
`android/` (`git diff --stat`), so no Rust source differs. Every check run on the PR heads was
success before each merge: PR #157 head `bdb194a` (19 check runs, including Android CI
`build`, `connected-tests` and `two-devices`), PR #158 head `c3ca851` (18), PR #163 head
`25f416a` (18, including `build`, which runs the JVM tests, `connected-tests` and
`two-devices`). Push CI on the merge commits `3e4e0c3`, `ddca7cc` and `0a8dbd4`: every run
success. The merges were made on the Owner's instructions of 2026-11-14. Emulators and a
local relay only; no phone (`NV`).

| ID | Status at `0a8dbd4` | Evidence (`main` @ `0a8dbd4`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-7 (b)** (Bluetooth permissions for the BLE stub) | **FIXED — merged** in PR #157 (merge `3e4e0c3`). The manifest requests only `INTERNET` and `ACCESS_NETWORK_STATE`. The unused stubs `BluetoothMeshManager`, `SolanaClient` (with the `SOLANA_RPC_URL` build field and Gradle property) and `ContactRepository` are deleted. `MessageRepository` is kept because two tests use it. With R-7 (a), (c) and (d) fixed earlier, every part of R-7 is now fixed. | `android/app/src/main/AndroidManifest.xml:4`, `:6`; the three files are absent under `android/app/src/main/kotlin/com/arcium/messenger/`. Independent review (`engineering-code-review` and `arcium-security-review`, full coverage): no security findings. | `SV`; CI `RV`; install-time behaviour on a phone `NV` |
| **R-10** (a missing history entry fails more) | **FIXED — merged** in PR #158 (merge `ddca7cc`). A missing entry number is skipped by every history read. Pages walk back over a gap and still hold up to `limit` entries; an empty page still means the beginning. An entry that exists but cannot be read is still an error. Without gaps, every read returns what it returned before. | `entries_in` (`crates/mobile-ffi/src/network/chat.rs:898`), `newest_before` (`:913`), the summary's last entry (`:527`), `open_entries` (`:931`, skip at `:936`), the record build in `open_seqs` (`:949`, skip at `:964`). Tests: `tests::history_paging::a_missing_entry_is_skipped_rather_than_failing_every_read` (`crates/mobile-ffi/src/tests/history_paging.rs:262`) and `…::an_open_entry_missing_from_the_store_is_skipped_by_rounds` (`:311`). Both fail on `de328a1`'s `chat.rs` with "storage error: key not found" and pass here. Specification: `docs/NET-MESSAGING.md:495`. **Remaining:** a damaged store is neither detected nor repaired, and the user is not told that an entry is gone (D-009 / F-10: the store claims no row-set integrity). A record number whose entry went missing stays in the open-entry record, harmlessly. | `SV`, tests `RV` |
| **R-17** (Android shows "Connected" while rounds fail) | **FIXED — merged** in PR #163 (merge `63b606d`). A round that reached the relay but reported another error is `RelayLink.Online` with that error as `problem`. The round-budget notice is not counted, since it is not an error (`docs/NET-MESSAGING.md` section 7). The banner on the contacts and chat screens then reads "Connected to the development relay, but the last sync reported: …" in the error colour. A network error is still `Offline`, with the same reason as before. | `RelayLink.Online` (`android/app/src/main/kotlin/com/arcium/messenger/messaging/MessengerService.kt:41`), `BUDGET_NOTICE` (`:55`), `linkAfterRound` (`:62`), used at `:197`; the banner (`android/app/src/main/kotlin/com/arcium/messenger/ui/contacts/ContactsScreen.kt:117`). JVM test `RelayLinkTest` (`android/app/src/test/kotlin/com/arcium/messenger/messaging/RelayLinkTest.kt`: a clean round, the notice alone, local errors with and without it, network errors with others). **Remaining:** the banner shows Rust's error text as it is, without advice. The notice is matched by a text prefix that copies the Rust constant `BUDGET_EXHAUSTED`. There was no independent review of this PR. | `SV`; CI `RV`; phone `NV` |
| **F-15 (a)** (Solana RPC path bypasses Tor) | Cross-reference only; the status is unchanged. The cited `SolanaClient.kt` was deleted by PR #157, so the app now has no Solana RPC path at all. The design concern returns when PSI is wired into the app (F-4, F-14, R-19). | `android/app/src/main/kotlin/com/arcium/messenger/network/SolanaClient.kt` absent at `0a8dbd4` | `SV` |

---

## Update 2026-11-14: delete a contact (`main` @ `6714921`)

**Snapshot:** `main` @ `67149214cb2da6084b4ea4f6181deb03d6287e7f`, the merge commit of PR #165
(session recovery option C of `docs/SESSION-RECOVERY-OPTIONS.md`, chosen under the Owner's
delegation of 2026-11-14). Only the notes below are added; every row keeps its snapshot and
status. Each `path:line` was re-read at `6714921`.

**Runtime evidence.** At `6714921`, `cargo test --workspace --locked`: exit 0, 507 passed,
0 failed, 4 ignored (local run, 2026-11-14). Every check run on PR #165's head `826d2b5` was
success (20 runs; `two-devices` passed on one re-run after an Android SDK download failure
that happened before any test ran). An independent review (`engineering-code-review`,
`arcium-security-review`, full coverage) found nothing a remote party can trigger. Its MEDIUM
finding (writes outside rounds re-creating a deleted contact's records) and LOW finding (a
damaged outbox record read as delivered) were fixed in the PR. Emulators and a local relay
only; no phone (`NV`).

| ID | Note at `6714921` | Evidence | Label |
|----|-------------------|----------|-------|
| **R-13** (false conflict dead end) | Still **OPEN**. Its cause is unchanged: a handshake alone still raises the conflict. A **way out now exists**: both users delete each other (`delete_contact`) and exchange cards again, and the next texts are delivered both ways. Undelivered texts are lost, and the peer is told nothing. Options A and B of `docs/SESSION-RECOVERY-OPTIONS.md` remain for removing the cause and for recovering without both users acting. | `Messenger::forget_peer` (`crates/core-protocol/src/messaging/removal.rs:154`, one transaction in `forget_listed`, `:204`); `NetworkMessenger::delete_contact` (`crates/mobile-ffi/src/network/chat.rs:737`); every chat write checks the card in its own transaction (`pinned_in`, `:438`). Test `tests::delete_contact::deleting_each_other_ends_the_dead_end_of_a_false_conflict` (`crates/mobile-ffi/src/tests/delete_contact.rs:141`) reproduces the dead end and then the recovery. Specification: `docs/S2-B2-DURABLE-MESSAGING.md:294`, `docs/NET-MESSAGING.md:492`. | `SV`, tests `RV` |
| **R-14** (more than `MAX_SKIP` lost messages) | Still **OPEN**, with the same way out as R-13. It was not reproduced end to end with a delete (`NV`); the mechanism is the same, since a delete removes the session in any state. | as for R-13 | `SV`; recovery `INF` |
| **R-15** (no failed state, no give-up) | Still **OPEN**. Deleting the contact now gives up every pending text, which is marked abandoned and never shown as delivered. A per-text cancel and a failed state are still missing. | `tests::delete_contact::a_text_without_a_receipt_is_abandoned_by_the_delete_not_delivered` (`delete_contact.rs:270`) | `SV`, test `RV` |
| **X-4** (delivery consistency) | Cross-reference only. A third exported path now takes texts out of the outbox: `delete_contact`. It marks them abandoned, also when an outbox record cannot be decoded (abandoned by the id in its key). The export guard allows exactly `resolve_session_conflict` and `delete_contact`. | `crates/mobile-ffi/src/tests/ack_probe.rs` (`neither_outbox_removal_is_exported_through_uniffi`); `core_protocol` test `forgetting_marks_an_undecodable_outbox_message_abandoned` | `SV`, tests `RV` |

**Limits.** Both users must delete. A sync round that runs at the same time as
`delete_contact` can start a new session for the deleted peer; the Android app runs both on
its one sync thread (`MessengerService.callBetweenRounds`), and the Rust doc states the
requirement for any other caller. Deleting the contact also removes the identity pin, so a
re-add trusts whatever card the user enters, as a first add does.

---

## Update 2026-11-14: R-16 fixed (`main` @ `6d6acea`)

**Snapshot:** `main` @ `6d6aceaf236e01f20580a2c18c2d36064f3e918d`, the merge commit of PR #167.
Only the row named here changes; every other row keeps the snapshot it cites. Each
`path:line` was re-read at `6d6acea`.

**Runtime evidence.** On PR #167's head `fa7a0c9` (based on `6714921`),
`cargo test --workspace --locked`: exit 0, 508 passed, 0 failed;
`cargo clippy --workspace --locked --all-targets -- -D warnings`: exit 0 (local run,
2026-11-14). `6714921` → `6d6acea` changes no Rust source except PR #167's (`git diff --stat`:
only `crates/mobile-ffi/src/network.rs` and `crates/mobile-ffi/src/tests/first_contact.rs`
under `crates/`). Every check run on the head was success (18 runs, including `two-devices`
and `connected-tests`). An independent review found no findings. The merge was made on the
Owner's instruction of 2026-11-14 ("мёрдж #167"). Local test relay only; a real relay restart
and a phone are `NV`.

| ID | Status at `6d6acea` | Evidence (`main` @ `6d6acea`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-16** (a lost refusal is not repeated until the responder restarts) | **FIXED — merged** in PR #167 (merge `6d6acea`). The per-process record of refused handshakes (`sent_for`) is gone. A retransmitted handshake is refused again once `REFUSAL_INTERVAL` (10 minutes) has passed since the last refusal to that contact; the per-contact limit is unchanged (at most one refusal per contact per interval). A repeated refusal cannot disturb a newer session: only the current unconfirmed session whose handshake hash matches is restarted. No wire or record format changed. **Remaining:** after a loss the initiator can wait up to the interval for the repeat; the limit is in memory, so a restart may send one more (as before). | `queue_refusal` (`crates/mobile-ffi/src/network.rs:1032`, the per-contact check `:1040-1047`, recorded `:1100`); `REFUSAL_INTERVAL` (`:200`). Tests: `tests::first_contact::a_lost_refusal_is_sent_again_once_the_interval_has_passed` (`crates/mobile-ffi/src/tests/first_contact.rs:326`; fails on `6714921`'s `network.rs`, passes here), `…::a_retransmitted_handshake_is_refused_once_per_interval` (`:294`), `…::a_second_refusal_to_one_contact_waits_for_the_interval` (`:250`). Specification: `docs/NET-MESSAGING.md:299-304`. | `SV`, tests `RV`; real relay restart `NV` |

---

## Update 2026-11-14: R-15 fixed (`main` @ `2cc79ff`)

**Snapshot:** `main` @ `2cc79ff4fff37d525bdb2240640149870b8a5079`, the merge commit of PR #169.
Only the rows named here change; every other row keeps the snapshot it cites. Each
`path:line` was re-read at `2cc79ff`.

**Runtime evidence.** On `6d6acea` plus PR #169 (its head `5632ab6`; `6d6acea` → `2cc79ff`
differs from that only by tracker PR #168, docs only), `cargo test --workspace --locked`:
exit 0, 515 passed, 0 failed, 4 ignored; `cargo clippy --workspace --locked --all-targets --
-D warnings`: exit 0 (local run, 2026-11-14). Every check run on the head was success (20
runs, including Android CI `build`, which runs the JVM tests, `connected-tests` and
`two-devices`). An independent review (`engineering-code-review`, `arcium-security-review`,
every changed file read in full) found no way for a text to read `Delivered` without the
peer's receipt; its MEDIUM finding (a text committed by a concurrent `refresh` published
once after the cancel) and a JVM-test import error were fixed in the PR. The merge was made
on the Owner's instruction of 2026-11-14 ("мёрдж #169"). Emulators and a local relay only;
no phone (`NV`).

| ID | Status at `2cc79ff` | Evidence (`main` @ `2cc79ff`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-15** (an unacknowledged text stays `Transmitted` for good; no give-up) | **FIXED — merged** in PR #169 (merge `2cc79ff`), as a per-text user cancel (the product decision taken under D-026/D-027 of the continuity records). `cancel_text` marks an own `Queued`, `Pending` or `Transmitted` text `Cancelled` in one transaction, then abandons its committed message; `publish_pending` abandons, instead of sending, any text whose entry reads `Cancelled` (a crash between the two steps, or a text another thread commits after the mark). A receipt already taken makes the entry `Delivered`; `Cancelled` → `Delivered` is the only move out of `Cancelled`. `Cancelled` claims nothing about the peer: a copy the relay already accepted may still be accepted there. Android offers "Cancel" (with a confirmation) on texts not yet final, run between rounds, and "Send again" (a new message) on cancelled ones. No wire, protocol or crypto change. **Remaining:** there is still no automatic give-up: a text the user does not cancel is retransmitted for as long as the app runs (by choice; "Not in this package" of the work plan). A crash inside a cancel that a receipt races can leave a delivered text `Cancelled`. A build without the new state code (6) reads such an entry as corrupt (downgrade). A round already past the publish check may send the text once more (Android cancels between rounds). | State and code (`crates/mobile-ffi/src/network/chat.rs:77`, `:89`, `:101`); the transitions (`:470`); `cancel_text` (`:751`); `cancelled_text` (`:1240`), checked in `publish_pending` (`crates/mobile-ffi/src/network.rs:867`). Tests `tests::cancel_text::*` (`crates/mobile-ffi/src/tests/cancel_text.rs:86`, `:122`, `:147`, `:180`, `:198`, `:229`) and `tests::network_crash::a_sender_killed_while_cancelling_never_sends_the_text` (`network_crash.rs:300`; with the `publish_pending` check disabled it fails). Android: `ChatScreen.kt:287`, `:291`; `ChatViewModel.kt:194`; JVM test `CancelActionsTest`. Specification: `docs/NET-MESSAGING.md:517`. | `SV`, tests `RV`; phone `NV` |
| **X-4** (delivery consistency) | Cross-reference only. A third exported caller of `abandon_outgoing` exists, `cancel_text`; the export guard lists it explicitly (`ALLOWED`, three names) and still checks every other exported method. `Delivered` still comes only from an acknowledged send record. | `crates/mobile-ffi/src/tests/ack_probe.rs:230`, `:253` | `SV`, test `RV` |

---

## Update 2026-11-14: R-18 (a) and (c) fixed (`main` @ `92ad8eb`)

**Snapshot:** `main` @ `92ad8eb4ac7e3c50579eab462562882012f7243f`, the merge commit of PR #171.
Only the row named here changes; every other row keeps the snapshot it cites. Each
`path:line` was re-read at `92ad8eb`.

**Runtime evidence.** Every check run on PR #171's head `bd596d0` was success (18 runs,
including Android CI `build`, which runs the JVM tests, Android Instrumentation
`connected-tests` on an API 30 emulator, and `two-devices`). No Rust source changed. There
was no local Android build (no SDK in the session). The merge was made on the Owner's
instruction of 2026-11-14 ("мёрдж #171"); the choice of items followed the Owner's
delegation of the same day (continuity record D-029). Emulators only; no phone (`NV`).

| ID | Status at `92ad8eb` | Evidence (`main` @ `92ad8eb`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-18** (Android hardening not present) | **PARTIAL — (a) and (c) fixed, merged** in PR #171 (merge `92ad8eb`); **(b) deferred**. (a) `MainActivity` sets `FLAG_SECURE`, so the system keeps the window out of screenshots, screen recordings and the recent-apps preview; the user cannot screenshot their own chats either. (c) `android:dataExtractionRules` excludes every domain, device-protected storage included, from cloud backup and device-to-device transfer on Android 12 and later; `allowBackup="false"` covers older versions. (b) StrongBox and Keystore key flags stay as they were: emulators have no StrongBox, so a fallback could not be verified, and a failing key creation would block start-up; an unlocked-device or user-authentication requirement would also block the planned background receive. It waits for a phone test. | (a) `android/app/src/main/kotlin/com/arcium/messenger/MainActivity.kt:24`; instrumentation test `ui/SecureWindowInstrumentationTest` (`android/app/src/androidTest/kotlin/com/arcium/messenger/ui/SecureWindowInstrumentationTest.kt:25`). (c) `android/app/src/main/AndroidManifest.xml:10-11`, `android/app/src/main/res/xml/data_extraction_rules.xml`; JVM test `security/BackupRulesTest` (`android/app/src/test/kotlin/com/arcium/messenger/security/BackupRulesTest.kt:25`, `:32`). (b) unchanged: `KeyGenParameterSpec.Builder` (`android/app/src/main/kotlin/com/arcium/messenger/security/MasterKeyProvider.kt:150`). | `SV`, CI `RV`; phone behaviour `NV` |

---

## Update 2026-11-14: option A (R-13), R-19 and background receive (`main` @ `efd4c0e`)

**Snapshot:** `main` @ `efd4c0edee678710107a4f532907048145767064`, the merge commit of PR #174.
Only the rows named here change; every other row keeps the snapshot it cites. Each
`path:line` was re-read at `efd4c0e`. The three PRs were merged on the Owner's instruction
of 2026-11-14 ("173, 175, 174 … Исполняй"); the designs follow the Owner's decisions of the
same day (continuity record D-029).

**Runtime evidence.**
- PR #174 (head `0a75fa7`): `cargo test --workspace --locked` 532 passed, 0 failed, and
  `cargo clippy --workspace --locked --all-targets -- -D warnings` exit 0 at its review fix
  `b2d1088`; the merge after it brought in Android and docs only. 19 check runs success on
  the head.
- PR #175 (head `361d5d1`): 12 check runs success (Arcium CI, two runs).
- PR #173 (head `cb38d45`): 18 check runs success, including Android CI `build` (JVM tests),
  `connected-tests` and `two-devices`.
- Each PR had an independent review (`engineering-code-review`, `arcium-security-review`)
  before the merge, and its findings were fixed in the PR. #175 was reviewed by the session
  agent, not a separate one.
- Emulators, a local relay and localnet only: no phone, no production relay, no devnet
  (`NV`).

| ID | Status at `efd4c0e` | Evidence (`main` @ `efd4c0e`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-13** (a false conflict dead-ends the conversation) | **PARTIAL — the forgeable trigger is removed** (option A, PR #174, merge `efd4c0e`). A handshake that arrives beside this device's own unconfirmed session is recorded there and raises nothing; the conflict is raised only when the contact's first message under that handshake authenticates (in memory: nothing written, no one-time prekey consumed, our session untouched). A forged handshake or message therefore no longer leads to the dead end. **Remaining:** a genuine handshake and first message replayed later can still raise a conflict when this device never accepted that handshake and its one-time prekey is still current; a dead end then also needs the contact to have given that session up, its messages withheld until the resolve, and the user to resolve (S2-B2 section 4c). The way out stays deleting the contact on both devices. Option B is still open. Two steps beyond the option A outline, approved with the merge: an unanswerable handshake beside our session queues the R-1 refusal, and the conflict flag moved to a new bit (the old one, raised by a handshake alone, is no longer read). | `Messenger::record_handshake_beside` (`crates/core-protocol/src/messaging/beside.rs:56`), `first_message_authenticates` (`:130`), `discard_beside` (`:169`); `responder_session` (`crates/mobile-ffi/src/lib.rs:1028`), `beside_authenticates` (`:1217`); the message branch (`crates/mobile-ffi/src/network.rs:1028`), `record_beside` (`:1089`); `FLAG_CONFLICT` (`crates/mobile-ffi/src/network/chat.rs:47`). Tests `tests::false_conflict::*` (`crates/mobile-ffi/src/tests/false_conflict.rs:176`, `:227`, `:269`, `:341`, `:417`, `:462`, `:495`; the first seven fail on `4266537`), `messaging::tests::beside`, two crash tests. Specification: `docs/S2-B2-DURABLE-MESSAGING.md:200`. | `SV`, tests `RV`; replay residual `INF` |
| **R-19** (PSI circuit registered on chain) | **FIXED in code — merged** in PR #175 (merge `fcabf55`); **not yet deployable**. `init_psi_intersect_comp_def` registers an off-chain source: a release URL and the SHA-256 of the compiled `build/psi_intersect.arcis`, both program constants, so no caller chooses them. The arcium-build CI job fails if the constant, `build/psi_intersect.hash` and the URL disagree, or if the built program lacks the URL. The localnet MPC scenarios run on a build with `ARCIUM_PSI_LOCALNET_ONCHAIN_CIRCUIT` set (the localnet Arx nodes refuse private-address URLs); the deploy build is checked for its registration only. **Remaining:** the circuit file is not published (that needs the Owner's approval, `docs/HOME-DEPLOY.md` Step 1b); no computation has run against the off-chain source; whether the Arx nodes follow GitHub's redirect is unknown. | `PSI_INTERSECT_CIRCUIT_HASH` (`arcium-psi/programs/arcium-psi/src/lib.rs:18`), `PSI_INTERSECT_CIRCUIT_URL` (`:29`), `psi_intersect_circuit_source` (`:39`), used at `:88`; the "Verify build artifacts" step and the `off-chain-registration` scenario in `.github/workflows/arcium-ci.yml`. | `SV`, CI `RV`; fetch by Arx nodes `NV` |
| **R-18** (Android hardening) | Note only; status unchanged (PARTIAL). With background receive on, the store stays open with its key in memory while the service runs, also on a locked device; an unlocked-device or user-authentication key flag (item b) would bear on starting the process without the user, which the service does not do. | `android/README.md:77` ("Background receive") | `SV` |
| **R-5** (retransmission) | Note only; status unchanged. Retransmission now also runs while the app is closed if the user turned background receive on (PR #173, merge `d36a95e`): an idle round every 30 s instead of 4 s on screen; the backoff is unchanged. Battery and data cost not measured. | `BACKGROUND_IDLE_DELAY_MS` and `idleDelayMs` (`android/app/src/main/kotlin/com/arcium/messenger/messaging/BackgroundRules.kt:58`, `:61`); `BackgroundReceiveService` (`android/app/src/main/kotlin/com/arcium/messenger/messaging/BackgroundReceiveService.kt:44`) | `SV`; cost `NV` |

---

## Update 2026-11-14: production relay (`main` @ `bd5dfed`)

**Snapshot:** `main` @ `bd5dfed0206e796ae8ea6793ac0f42df5ee709ca`. The relay work is the
merges of PRs #179 (`9c36cf0`), #180 (`9b3f54f`), #181 (`b41050d`) and #182 (`bc0dc19`); the
merge after them, PR #183, changed instruction files only. Only the rows named here change;
every other row keeps the snapshot it cites. Each `path:line` was re-read at `bd5dfed`. The
four PRs were merged on the Owner's instruction of 2026-11-14 ("мёрдж #179, #180, #181,
#182"); the Owner delegated the relay design (continuity record D-032).

**Runtime evidence.**
- PR #179 (head `e3a0578`): 18 check runs success; `cargo test --workspace --locked` 543
  passed locally.
- PR #180 (head `a830d99`): 18 check runs success; 572 passed locally (stable 1.100).
- PR #181 (head `9385596`): 19 check runs success, including Android CI `build`,
  `connected-tests` and `two-devices`; 580 passed locally.
- PR #182 (head `95498de`, docs only): 12 check runs success.
- Each code PR had an independent review (`engineering-code-review`,
  `arcium-security-review`), and its findings were fixed in the PR. The review of #181
  found the R-9 residual below with a probe (not committed).
- Loopback only. No real server, no phone and no release build ran (`NV`).

| ID | Status at `bd5dfed` | Evidence (`main` @ `bd5dfed`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-9** (a reader of a mailbox learns whom its owner has pinned) | **OPEN — narrowed.** On a `RELAY_PROTOCOL_V2` relay a stranger can no longer read, delete or replace a mailbox: FETCH, FETCH_AFTER, DELETE and PUT_BUNDLE are answered only for the owner who authenticated on that connection, over TLS 1.3 to the pinned relay key. Release builds of the app accept only V2. **Remaining:** anyone may SEND (first contact needs it), and the SENDs accepted before FULL count a mailbox's free places. Planting forged messages that name X, waiting for the owner's round and counting again shows whether they were kept, that is, whether X is pinned (probe in the #181 review: with a cap of 10, 7 places left after forged messages from a pinned X against 10 from a stranger). The attack fills the mailbox, so it is visible. The relay's operator reads everything; V1 (development builds) is unchanged. The keep-versus-delete rule itself is unchanged. | `Session::screen` (`crates/relay/src/server.rs:539`); `NetworkMessenger::connect_owner` (`crates/mobile-ffi/src/network.rs:570`); keep on `NoSession` (`:1092`); `relayChoice` (`android/app/src/main/kotlin/com/arcium/messenger/messaging/RelayRules.kt:30`, V1 refused at `:35`); `docs/NET-MESSAGING.md:131`, `:489`. Tests `tests::relay_v2::only_a_mailboxs_owner_can_read_or_delete_it_or_publish_its_bundle` (`crates/mobile-ffi/src/tests/relay_v2.rs:85`), `v2_tests::without_auth_only_send_and_get_bundle_are_answered` (`crates/relay/src/v2_tests.rs:151`), `v2_tests::after_auth_another_owners_mailbox_and_bundle_are_unauthorized` (`:125`). | `SV`, tests `RV`; residual `RV` (probe, not committed) |
| **R-14** (more than `MAX_SKIP` lost messages stop a direction) | **OPEN — narrowed.** Two of its causes are closed for a relay run as `docs/RELAY-DEPLOY.md` describes (V2 with `--db`). A restart no longer loses accepted envelopes: SEND, DELETE and a changed bundle are committed to SQLite (WAL, `synchronous=FULL`) before the answer. And strangers can no longer delete receipts (DELETE needs the owner's AUTH, as for R-9). **Remaining:** the relay's operator can still delete or withhold; a relay without `--db`, and any V1 relay, keep the old behaviour; more than 1000 consecutive losses in one sending chain still stop that direction, and the way out is still deleting the contact on both devices. | write-through in `handle` (`crates/relay/src/server.rs:642`, `:699`, `:734`); `Disk::store_envelope` (`crates/relay/src/disk.rs:243`), `synchronous` set at `:124`; `MAX_SKIP` unchanged. Tests `a_relay_with_a_database_keeps_mailboxes_and_bundles_across_restarts` (`crates/relay/src/lib.rs:118`), `v2_tests::persistence_works_under_v2` (`crates/relay/src/v2_tests.rs:220`). | `SV`, tests `RV`; power loss `NV` |
| **R-8** (one full mailbox stopped every round) | Note only; status unchanged (FIXED, with its remaining item). The remaining item — delivery to a full mailbox's owner stays blocked until it has room — is not closed by V2: V2 authenticates owners, not senders, so anyone can still fill a mailbox. New for every relay: the envelope bytes of all mailboxes together are capped (default 1 GiB, refused with FULL beyond it). | `RelayConfig::max_total_bytes` (`crates/relay/src/server.rs:98`), default at `:107`; `Session::screen` lets SEND through unauthenticated (`:542`). | `SV` |

---

## Update 2026-11-15: R-20 … R-22 and status words (`main` @ `3f104e9`)

**Snapshot:** `main` @ `3f104e941147d52a5f9e59ac65ea622a640fe6ad` (the merge of PR #187).
Three new rows, found by the project classification pass of 2026-11-15 and each re-read in
source at `3f104e9` for this update; a note on H-7's anchors; and the status words used from
here on. No earlier row is changed. Nothing here was reproduced at runtime: the labels say
what was read and what is inferred.

### New rows

| ID | Sev | Item | Anchor (`main` @ `3f104e9`) | Label |
|----|-----|------|-----------------------------|-------|
| **R-20** | LOW | **Cancelling texts that were already encrypted leaves a hole in the sending chain.** `send` encrypts at once and commits the new chain state with the outbox record, so the message number is used up (`ns += 1`). `cancel_text` then abandons the pending message: it leaves the outbox and is never sent, and nothing gives the number back. The receiver sees a gap; each gap stores skipped keys (see R-21), and a gap of more than `MAX_SKIP` (1000) in one chain makes the receiver refuse every later message of that chain — the same dead end as R-14. **Status: OPEN.** | `crates/core-protocol/src/messaging.rs:426-462` (`send`, encrypt then commit); `crates/core-crypto/src/ratchet.rs:182-194` (`encrypt`, `ns += 1`); `crates/mobile-ffi/src/network/chat.rs:764-800` (`cancel_text` → `abandon_outgoing`); `crates/core-protocol/src/messaging/removal.rs:22-45` (`abandon_outgoing`, no chain change); `ratchet.rs:41, 297` (`MAX_SKIP`) | `SV` (mechanism); `INF` (reachability: needs the local user to cancel more than 1000 encrypted texts in a row with none delivered after them; no remote party causes it) |
| **R-21** | LOW | **A late message whose skipped key was evicted is lost for good, and its sender keeps resending it.** The ratchet keeps at most 2000 skipped keys and drops the oldest first. When a message arrives after its key was dropped, decryption fails, and the round deletes it like any message that does not decrypt (`CoreError::Crypto` → `Fate::Delete`). The sender's outbox holds the same ciphertext and retransmits it until a receipt that cannot come, so the text stays `Transmitted` until the user cancels it (R-15). **Status: OPEN.** | `crates/core-crypto/src/ratchet.rs:131, 148` (`max_skipped: 2000`), `:345-352` (`trim_skipped`, FIFO); `crates/core-crypto/src/ratchet/checkpoint.rs:102` (`MAX_SKIPPED_KEYS = 2000`); `crates/mobile-ffi/src/network.rs:1093-1132` (the `Crypto` branch deletes) | `SV` (mechanism); `INF` (reachability: more than 2000 messages must be missing at once and the evicted one delivered later — loss, or a relay operator that withholds and then releases; R-20's holes count too) |
| **R-22** | INFO | **`last_sent` only grows for the life of the process.** It records each message and handshake the relay accepted (32-byte id, time, count) and is read for retransmission backoff. Entries are inserted and updated, never removed, also not when a message is acknowledged or a contact is forgotten (`forget_peer` says so). Memory only, so a restart clears it; with the foreground receive service the process can live for days. Roughly tens of bytes plus map overhead per message sent. **Status: OPEN.** | `crates/mobile-ffi/src/network.rs:143` (field), `:379` (created), `:869-873` (`mark_sent`, insert only); `crates/mobile-ffi/src/network/chat.rs:906-907` (comment: entries of a forgotten contact stay) | `SV` (no removal: `grep` finds no `remove` or `retain` on `last_sent`); `INF` (size; not measured) |

### Notes on rows above

| ID | Note | Label |
|----|------|-------|
| **H-7** | Anchors drifted, status unchanged (OPEN). The `mobile-ffi` copy sites are now `crates/mobile-ffi/src/lib.rs:266, 422, 432` (the row names `377, 387, 610`); `ratchet/checkpoint.rs:324` and `hybrid.rs:120` still match. The same by-value pattern exists at `crates/relay/src/auth.rs:150, 206`, outside the row. | `SV` |
| **F-17 record** | The closure record cites `CLAUDE.md` sections by older names («Правила работы», «Что за проект»). Since PR #186 (`6f3a5e6`) the file has no such headings; the rule against inventories is in its opening section. The record keeps the snapshot it cites. | `SV` |

### Status words from here on

Earlier rows use several words for the same states (`NOT-FIXED`, `PARTIALLY_FIXED`,
`NEEDS-HOME`, rows with no status word). They keep them; read them by this table. Rows and
updates from this one on use only the five words on the left.

| Word | Meaning | Earlier words read as it |
|------|---------|--------------------------|
| **OPEN** | The defect is present at the cited SHA. "OPEN — narrowed" says part of it was closed. | `NOT-FIXED`; `NOT-FIXED (design)`; an H-row with no status word (H-2, H-6, H-7, H-8: the H-series introduction says the rest are recorded and not fixed) |
| **PARTIAL** | Named parts are fixed; the row lists what is not. | `PARTIALLY_FIXED`; `PARTIAL` |
| **FIXED** | Fixed by a merged PR named in the row. A "remaining item" in a FIXED row is a limit of the fix, not an open defect, unless a later row opens it. | `FIXED — merged`; `FIXED` |
| **ACCEPTED** | The Owner accepted the residual; the row names the decision. | `ACCEPTED` |
| **NOT A DEFECT** | Checked and found harmless as used. | `VERIFIED-BENIGN` |

Severity (`CRITICAL` … `INFO`) is a separate column and never a status. What a row waits for
(home deploy, a phone, an Owner decision) is written in the row, not as a status:
`NEEDS-HOME` is such a blocker, attached to an OPEN row.

---

## Update 2026-11-15: H-7 narrowed (`main` @ `79be252`)

**Snapshot:** `main` @ `79be252` (the merge of PR #190). The H-7 change is PR #189, merged
as `14e77a0` on the Owner's instruction of 2026-11-15. Only the H-7 row changes; every other
row keeps the snapshot it cites. Each `path:line` was re-read at `79be252`.

**Runtime evidence.** PR #189 (head `62ffde8`): 18 check runs success, including
`core-rust`, `connected-tests` and `two-devices`; `cargo test --workspace --locked` 580
passed, 0 failed locally. Its local `arcium-security-review` reported no finding at full
coverage of `hybrid.rs`. Analysis, not proof; compiled code and device memory were not
examined.

| ID | Status at `79be252` | Evidence (`main` @ `79be252`) | Label |
|----|---------------------|-------------------------------|-------|
| **H-7** (copies of secret arrays are not wiped) | **OPEN — narrowed.** `HybridSecretKey` now holds the X25519 secret as a `StaticSecret`, which wipes itself on drop, and `hybrid_decaps` borrows it: the per-decapsulation copy (`StaticSecret::from(sk.x25519)`) is gone. Keygen still leaves one moved-from location, as before. **Remaining:** the four sites that load a secret from stored bytes, where the bytes are already in `Zeroizing` and the unwiped copy is the by-value argument of `StaticSecret::from([u8; 32])`, x25519-dalek 2.0.1's only constructor from bytes. Removing it needs an upstream API or `unsafe`; neither is proposed. The same pattern at `crates/relay/src/auth.rs:150, 206` stays outside the row. Whether any copy persists in memory remains inferred (see H-8). | `crates/core-crypto/src/hybrid.rs:38` (field), `:123` (borrowed in decaps), `:377-380` (test pins `Zeroize` and drop); remaining: `crates/core-crypto/src/ratchet/checkpoint.rs:324`, `crates/mobile-ffi/src/lib.rs:266, 422, 432` *(Note 2026-11-21: the `lib.rs` anchors here moved in PR #241; see "Update 2026-11-21: code locations after the split". Status unchanged.)* | `SV` (code); `RUNTIME_VERIFIED` (tests, PR #189); `INF` (persistence of copies) |

---

## Update 2026-11-16: R-23 and R-24 (C004 NEW-1, NEW-2) (`main` @ `b142ed7`)

**Snapshot:** `main` @ `b142ed732596fce3ea9373750094131e4ebbe798` (the merge of PR #193).
Two findings from the experimental C004 pass of 2026-10-30 (named NEW-1 and NEW-2 there,
found with a harness that was never committed) were not in this tracker. The code they
describe has not changed since. Each is re-read at `b142ed7` and reproduced for this
update with a probe test in a disposable clone; the probes are not committed. Recorded on
the Owner's instruction of 2026-11-16 ("Занеси NEW-1 и NEW-2 в трекер"). No earlier row is
changed.

### New rows

| ID | Sev | Item | Anchor (`main` @ `b142ed7`) | Label |
|----|-----|------|-----------------------------|-------|
| **R-23** (C004 NEW-1) | LOW (availability) | **Skipped-key eviction is not oldest-first once a late message has been read.** A late message's key is taken out with `IndexMap::swap_remove`, which moves the newest stored key into the freed slot. `trim_skipped` evicts from index 0 and assumes that index order is insertion order. After a `swap_remove` at or near the front, the cap evicts a recent key while older ones stay, and the message that key belongs to is lost for good (it fails to decrypt and is deleted, as in R-21). Confidentiality is not affected. The existing FIFO tests insert keys directly and never call `swap_remove`, so they do not see this. **Status: OPEN.** | `crates/core-crypto/src/ratchet.rs:240` (`swap_remove`), `:345-352` (`trim_skipped`), test `trim_skipped_fifo_oldest_evicted_newest_retained` (`:473`) | `SV`; `RUNTIME_VERIFIED` (probe: cap 3; Bob reads m3, then m0 late, then m6; afterwards the older m1 still decrypts and the newer m2 does not) |
| **R-24** (C004 NEW-2) | INFO (defence in depth) | **X3DH accepts low-order X25519 keys from the peer.** Neither `x3dh_respond` nor `x3dh_initiate` checks that a DH output is contributory, and a contact card's DH key is not checked either. With a low-order identity and ephemeral key from the initiator, every DH output is all-zero, so the root key is the same whatever the responder's identity, signed-prekey and one-time-prekey secrets are: anyone can compute it, not only the two parties. Only the party whose keys these are can cause it (the contact itself, or whoever supplied the pinned card), so it cannot reveal more than that party could leak anyway (`INF`). The refusal MAC already makes this check (`was_contributory`); the Ed25519 signing key already rejects small-order points (`verify_strict`). **Status: OPEN.** A fix changes the handshake and needs its own Owner task. | `crates/core-crypto/src/x3dh.rs:125-160` (`x3dh_initiate`), `:169-197` (`x3dh_respond`); `crates/mobile-ffi/src/contacts.rs:38-50` (`Card::decode`); the existing check at `crates/core-crypto/src/refusal_mac.rs:62` | `SV`; `RUNTIME_VERIFIED` at the `x3dh_respond` level (probe: two runs with different responder secrets and peer keys at u = 0 gave the same root key, with and without a one-time prekey); app level `NV` |

### Notes on rows above

| ID | Note | Label |
|----|------|-------|
| **R-21** | Its row says the ratchet drops "the oldest first". R-23 refines that: after a late message has been read, the dropped key need not be the oldest. The loss and its consequence are as R-21 describes. | `SV` |

---

## Update 2026-11-17: R-23 fixed (`main` @ `b1257df`)

**Snapshot:** `main` @ `b1257df0f7cd0b3759e30e3b480a27ffcfc1ccd8` (the merge of PR #196). The fix
was asked for by the Owner on 2026-11-17 ("Делай R-23") and merged on the Owner's
instruction ("мёрдж #196"). Each `path:line` below was re-read at `b1257df`.

**Runtime evidence.** PR #196 (head `dfc0c96`): 18 check runs success, including
`core-rust`, `connected-tests` and `two-devices`. Locally `cargo test --workspace --locked`:
581 passed, 0 failed. The new test fails with the old call put back (`left: [2, 1]`) and
passes with the fix. An independent review with a fresh context (`engineering-code-review`,
`arcium-security-review`, `mbr-integration`) reported only INFO items. A review is analysis,
not proof.

| ID | Status at `b1257df` | Evidence (`main` @ `b1257df`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-23** (skipped-key eviction not oldest-first after a late read) | **FIXED.** A late message's key is now removed with `shift_remove`, which keeps insertion order, so `trim_skipped` evicts the oldest key. **Remaining:** a checkpoint written by the old code keeps the order it had. Keys it reordered stay in that order until each is used or evicted; at most one key is out of place per late read made before the update. The order cannot be rebuilt from the record, so no code change is proposed. | `crates/core-crypto/src/ratchet.rs:242` (`shift_remove`), `:347-355` (`trim_skipped`), test `late_read_keeps_skipped_keys_in_insertion_order` (`:531`); the checkpoint writes the map in order (`crates/core-crypto/src/ratchet/checkpoint.rs:43, 244`) | `SV`; `RUNTIME_VERIFIED` (test; CI on `dfc0c96`); remaining part `INF` (from the code; not observed on real data) |
| **R-21** (late message lost when its skipped key is evicted) | Note only; status unchanged (OPEN). After the fix the evicted key is the oldest, as the row says; the loss itself remains. | as R-23 | `SV` |
| **H-6** (stale key copies in the `IndexMap`) | Note only; status unchanged (still listed under remaining work, item 5). The row names `swap_remove` and `ratchet.rs:108, 233, 342`; the late-read removal is now `shift_remove` at `ratchet.rs:242`. The review found that both calls leave the same single stale entry at the old last slot, so the exposure is unchanged. | `crates/core-crypto/src/ratchet.rs:242`; indexmap 2.14.2 `inner.rs:564-571` (`shift_remove`), `:587-602` (`swap_remove`) | `INF` (from the indexmap source; memory not observed) |

**Not established:** behaviour on a phone; any effect on stored data beyond what the code
shows; the cost of eviction under a forged header (the review's item 4, outside this fix).

---

## Update 2026-11-17: R-25 fixed, H-6 narrowed (`main` @ `e4e2313`)

**Snapshot:** `main` @ `e4e2313bed54e44e6f34e694c6480c28eacf8fa3` (the merge of PR #200). The work was
asked for by the Owner on 2026-11-17 ("вытесняй ключи", "1 вариант делай", "сразу
резервировать место под 2000 ключей при загрузке … закрой и всё остальное мерж"). Each
`path:line` below was re-read at `e4e2313`.

**Runtime evidence.**
- PR #199 (merged as `5061041`): 18 check runs success on head `d662ee0`. Locally `cargo test --workspace --locked` → 584 passed, 0 failed.
- PR #200 (merged as `e4e2313`): 18 check runs success on head `e95cd3f`. Locally → 586 passed, 0 failed.
- Fresh-context reviews (`engineering-code-review`, `arcium-security-review`, `mbr-integration`): three rounds on #199 and two on #200, each round on the version that fixed the previous round's findings. The last round on each PR found nothing at LOW or above. Reviews are analysis, not proof.

| ID | Status at `e4e2313` | Evidence (`main` @ `e4e2313`) | Label |
|----|---------------------|-------------------------------|-------|
| **H-6** (stale key copies in the skipped-key `IndexMap`) | **OPEN — narrowed.** Closed: (a) eviction no longer shifts the kept keys once per evicted key, and the new keys are written over the slots the eviction freed, so a full store leaves no copies of kept keys behind on the forged-header, repeated-DH and checkpoint paths (#199); (b) the entries buffer of a new or restored store, and of every copy (`staged_copy`, the rollback snapshot), has room for `MAX_SKIPPED_KEYS`, so it is never reallocated while it holds keys (#200). **Remaining:** the late-read `shift_remove` leaves one stale entry in spare capacity, freed unwiped with the map; copies of key bytes outside the map (stack, AEAD) are untouched. The row's anchors (`ratchet.rs:108, 233, 342`, `swap_remove`, `shift_remove_index`) are stale. | `crates/core-crypto/src/ratchet.rs:62-74` (`copy_skipped`), `:153, 172` (constructors), `:267` (late read), `:305` (snapshot), `:323` (`skip_message_keys`), `:384-387` (`trim_skipped`), `:405` (`make_room`); `crates/core-crypto/src/ratchet/checkpoint.rs:336, 382`; tests `skipping_into_a_full_store_does_not_grow_it` (`ratchet.rs:1420`), `a_new_or_restored_store_never_grows` (`:1477`), `copies_of_a_store_have_room_for_every_key` (`:1510`) | `SV`; `RUNTIME_VERIFIED` (tests; probes counting slots beyond `len` and entries reallocations, x86, uncommitted); freed memory not read (`NV`) |
| **R-21** (late message lost when its skipped key is evicted) | Note only; status unchanged (OPEN). Eviction order is unchanged by #199 (equal to the old code on random traces, repeated DH keys included). The row's anchor `ratchet.rs:345-352` is now `:384-387` and `:405`. | as above | `SV`; `RUNTIME_VERIFIED` (equivalence probes) |

### New rows

| ID | Sev | Item | Anchor (`main` @ `e4e2313`) | Label |
|----|-----|------|-----------------------------|-------|
| **R-25** | LOW (availability) | **A forged header with a new DH key and a large skip was expensive to reject.** Against a full skipped-key store (2,000 keys), a header with a new DH key, `pn = nr + 1000` and `n = 1000` made the receiver derive about 2,000 message keys and evict about 1,000 keys twice **one at a time**, each eviction an O(n) shift, before AEAD failed and the state was rolled back. Found by the review of #196 (item 4). **Status: FIXED** by #199: `make_room` evicts the excess in one `drain` before the new keys are inserted; the resulting store equals the old one in every case checked (random-trace comparison, repeated DH keys included). Release probe on x86 (counting `Zeroizing` stand-in): about 17 ms → about 1.2–1.3 ms per forged header; an ordinary forgery about 30 µs either way. **Remaining:** the up to 2 × 1,000 key derivations `MAX_SKIP` allows (by design); a phone was not measured. | `crates/core-crypto/src/ratchet.rs:323` (`skip_message_keys`), `:405` (`make_room`), `:384-387` (`trim_skipped`); `MAX_SKIP` (`:42`); tests `skipping_past_a_full_store_evicts_the_oldest_keys_once_each` (`:1373`), `a_repeated_dh_key_is_stored_and_evicted_as_before` (`:1440`) | `SV`; `RUNTIME_VERIFIED` (tests; probe, x86 release, uncommitted); phone `NV` |

**Cost of #200 (review, production `Zeroizing`, x86 glibc).** Each received message now
allocates and frees about 0.6–0.85 MB of short-lived buffers (the reserved store and its
copies), where a small store used to allocate a few KB. Time per in-order message rose from
about 3–4 µs to about 3.5–5.7 µs. Bounded; nothing accumulates. Android (scudo, arm64):
NOT_VERIFIED.

**Not established:** behaviour, time and memory on a phone; the contents of freed memory
(the probes count copies in live buffers and reallocations; they do not read freed memory).

---

## Update 2026-11-17: R-24 fixed (`main` @ `3767d94`)

**Snapshot:** `main` @ `3767d94a11c2a19abe41ca4a0b35307c531e307b` (the merge of PR #203). The fix was
asked for by the Owner on 2026-11-17 ("Делай R-24") and merged on the Owner's instruction
("мёрдж #203"). Each `path:line` below was re-read at `3767d94`.

**Runtime evidence.** PR #203: 18 check runs success on head `8a9f268`, including
`core-rust`, `connected-tests` and `two-devices`. Locally `cargo test --workspace --locked` →
591 passed, 0 failed on `8b2f8e4`; `cargo test -p mobile-ffi --locked --lib` → 210 passed,
0 failed on `8a9f268`. The two new mobile-ffi tests fail on the unfixed code (clean
build). A fresh-context review (`engineering-code-review`, `arcium-security-review`) found
nothing above INFO; a review is analysis, not proof.

| ID | Status at `3767d94` | Evidence (`main` @ `3767d94`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-24** (C004 NEW-2; X3DH accepts low-order X25519 peer keys) | **FIXED.** `x3dh_initiate` and `x3dh_respond` refuse the handshake (`X3dhError::LowOrderKey`) if any DH output is not contributory, so no root key is derived from a low-order identity, signed prekey, one-time prekey or ephemeral key. In the app, an initiator handshake with a low-order identity or ephemeral key is refused when decoded (`InvalidHandshake`), after every structural check: it is dropped on receipt, never recorded, and no refusal is sent. A key made from a secret never has low order, so honest peers are unaffected. **Remaining (INFO):** (a) a contact card's DH key is still not checked (`Card::decode`); a session with such a card now fails both ways, so nothing leaks; (b) a provisional handshake with a low-order key recorded by an older build makes its first message wait on the relay, with an error each round, until the contact's next handshake replaces the record (review probe; only possible if such a handshake arrived before this build). | `crates/core-crypto/src/x3dh.rs:32` (`LowOrderKey`), `:150, 190` (checks in `x3dh_initiate` / `x3dh_respond`), `:216` (`check_contributory`); `crates/mobile-ffi/src/lib.rs:587` (decode check), `:607` (`has_low_order`), `:1051` (`responder_session`); tests `x3dh.rs:608, 628, 661`, `mobile-ffi/src/lib.rs:2173, 2198`; `crates/mobile-ffi/src/contacts.rs:38` (`Card::decode`, unchanged) | `SV`; `RUNTIME_VERIFIED` (tests; CI on `8a9f268`); phone `NV` |

**Not established:** behaviour on a phone; a cryptographer's review; data from older builds.
The Double Ratchet DH step with `header.dh` is unchanged (its root key also mixes in the
previous root key; only the peer can choose that key) and is outside R-24.

---

## Update 2026-11-17: R-22 fixed (`main` @ `3f0cf9f`)

**Snapshot:** `main` @ `3f0cf9fa943b33b566bd42bd26ff956abd6aee1e` (the merge of PR #205). The fix was
asked for by the Owner on 2026-11-17 ("Делай R-22") and merged on the Owner's instruction
("Мерж"). Each `path:line` below was re-read at `3f0cf9f`.

**Runtime evidence.** PR #205: 18 check runs success on head `5977f8b` (one `two-devices`
run failed before any test ran, when the emulator refused the APK install with a broken
pipe; it passed on its one re-run, and the other `two-devices` run on the same head
passed). Locally `cargo test --workspace --locked` → 594 passed, 0 failed. Three new tests,
each failing when the behaviour it guards is removed. Two fresh-context reviews
(`engineering-code-review`, `arcium-security-review`); the second found nothing above LOW.
A review is analysis, not proof.

| ID | Status at `3f0cf9f` | Evidence (`main` @ `3f0cf9f`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-22** (`last_sent` only grows for the life of the process) | **FIXED.** After every sync round, also one that failed part way, `prune_sent` keeps an entry only while its key is the id of a pending outgoing message or the hash of a session's initiator handshake, or it was written after the pass began. Its two readers (`due`, `was_sent`) ask about nothing else. Delivered and abandoned messages, receipts and everything of a deleted contact are dropped, so the map is bounded by the pending messages plus one handshake hash per session. **Remaining (LOW, cost):** each `sync()` now reads and decrypts every session's outbox once more, also when the relay is unreachable; the review measured about 0.65 s per `sync()` with 500 pending 4 KB texts in a debug build (release and phone not measured; usual outboxes are small). **INFO:** the same store error can be reported twice; a corrupt stored handshake of a confirmed session would make the prune fail each round (it then drops nothing); the guard for parallel rounds has no test (the app runs rounds on one thread). | `crates/mobile-ffi/src/network.rs:144` (field), `:517` (call after every round), `:886` (`prune_sent`), `:851` (`was_sent`), `:861` (`due`), `:906` (`mark_sent`); tests `crates/mobile-ffi/src/tests/net_limits.rs:249, 286, 311` | `SV`; `RUNTIME_VERIFIED` (tests, mutations; CI on `5977f8b`); memory and time on a phone `NV` |

---

## Update 2026-11-18: R-21 partial (`main` @ `6e00a7f`)

**Snapshot:** `main` @ `6e00a7f680e4bcb0b47c6d28055d0aba058438e0` (the merge of PR #207). The fix was
asked for by the Owner on 2026-11-17 ("Делай R-21"), who chose the notification option
("Уведомление"), and merged on the Owner's "Ok" to "мёрдж #207". Each `path:line` below was
re-read at `6e00a7f`.

**Runtime evidence.** PR #207: 20 check runs success on head `de11751`, the Android
emulator jobs included. Locally `cargo test --workspace --locked` → 600 passed, 0 failed.
Six new tests (one in `core-crypto`, five in `mobile-ffi`) and extended wire tests; seven
mutations, each removing one guarded behaviour, each failed the test that guards it. Two
fresh-context reviews (`engineering-code-review`, `arcium-security-review`): the first found
one MEDIUM (a GONE lost on the relay was never sent again), fixed in the PR; the second
found nothing above LOW. A review is analysis, not proof.

| ID | Status at `6e00a7f` | Evidence (`main` @ `6e00a7f`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-21** (a late message whose skipped key was evicted is lost, and its sender keeps resending it) | **PARTIAL.** **Fixed for the current receiving chain:** a message of an existing session that does not decrypt, whose header names a position of the current receiving chain behind the next expected one with no skipped key stored for it, is named back to its sender in a new in-session payload, GONE (`PAYLOAD_V1` type 4, 1–256 message ids). The sender abandons each named id that is a text still pending: it is not sent again and its history entry reads `NotDelivered`. Any other id changes nothing. A GONE leaves the outbox once the relay accepted it; when the sender repeats a named message, a later GONE is committed at once, then at most once a minute. At most one GONE per session per round (the first 256 ids in id order); the in-memory collection is emptied after every round. The message itself stays lost: its key is gone. **Remains:** a late message of an older receiving chain (after a DH ratchet step) is only deleted, as before, and its sender keeps resending it until the user cancels it: the receiver does not keep old peer ratchet keys, and covering that chain was left out by the Owner's choice. **Residual (LOW, as R-12 for receipts):** a sender that does not act on a GONE (a build before GONE, or a pending message that is not a text) draws a later GONE at most once a minute for as long as it repeats, each leaving a send-id record (growth read from source, not measured). **INFO:** whoever saw a header of the current chain and can write to the mailbox (the relay operator; anyone on V1) can make altered copies that draw at most one GONE per session per round, naming ids the peer never sent (they change nothing there), or crowd the 256 places so that a genuine late message is never named; a relay can withhold the GONE anyway. A GONE's length shows how many ids it names. `sync_conversations` may run `sync()` twice, so up to two GONE per session per app round. | `crates/core-crypto/src/ratchet.rs:301` (`is_beyond_recall`), test `:1558`; `crates/core-protocol/src/durable.rs:669`; `crates/core-protocol/src/messaging.rs:414` (`beyond_recall`); `crates/mobile-ffi/src/messaging_api.rs:248`; `crates/mobile-ffi/src/network/wire.rs:40` (`TYPE_GONE`), `:229` (`client_id::gone`); `crates/mobile-ffi/src/network.rs:164` (collection), `:536` (emptied after every round), `:1040` (acknowledged once sent), `:1202` (check in the `Crypto` branch), `:1502` (sender abandons pending texts), `:1540` (`commit_gone`), `:1552` (`name_gone`), `:1595` (`this_minute`); tests `crates/mobile-ffi/src/tests/beyond_recall.rs:21, 140, 215, 233`; `docs/NET-MESSAGING.md:260` (section 4), `:531-547` (section 8) | `SV`; `RUNTIME_VERIFIED` (tests, mutations; CI on `de11751`); an older build receiving GONE and phones `NV` |

---

## Update 2026-11-18: R-14 and R-20 partial (`main` @ `7755efd`)

**Snapshot:** `main` @ `7755efdb4d2b71cbc9786c884c90e54010e8b5a6` (the merge of PR #209). The fix was
asked for by the Owner on 2026-11-18 ("Делай R-14"), who chose the far-skip option ("Дальний
прыжок"), and merged on the Owner's "Ок продолжай" to "мёрдж #209". Each `path:line` below was
re-read at `7755efd`.

**Runtime evidence.** PR #209: 18 check runs success on head `0392a57`, the Android emulator
jobs included. Locally `cargo test --workspace --locked` → 620 passed, 0 failed. Two network
tests reproduce R-14 and fail on `main`'s code; with the fix they pass. More than twenty
mutations, each removing one guarded behaviour, each failed its test. Five fresh-context
reviews (`engineering-code-review`, `arcium-security-review`). Review 2 found that skipping at
once turned a delay into a loss (probe: 1301 of 1501 texts delivered, 200 given up, where
`main` delivered all 1501), which led to the wait and the end-of-pass rule. The last review
found nothing above LOW. A review is analysis, not proof.

| ID | Status at `7755efd` | Evidence (`main` @ `7755efd`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-14** (more than `MAX_SKIP` lost messages in one sending chain stop that direction for good) | **PARTIAL.** **Fixed up to 100,000:** `DoubleRatchet::decrypt_far` skips up to `MAX_FAR_SKIP` (100,000) positions per chain, keeps the keys of only the last `MAX_SKIP` (1,000) it skips (the earlier ones are derived and wiped), and never ends past `MAX_RESUMABLE_NR` (the F-1 overflow bound); `decrypt` and commit-on-success are unchanged. The network layer tries it only for a gap nothing fills: once the session has seen far messages of that chain for `FAR_SKIP_WAIT` (10 minutes, twice the longest wait between retransmissions, counted from the chain's first arrival) without accepting a message, at the end of a message pass in which it accepted none; one try per session and four per round. Any other far message is deleted like one that does not decrypt (nothing kept on the relay, R-9), and read when it comes again. A lost text of the current chain from before the kept keys is named back with GONE (R-21) and reads `NotDelivered`. **Remains:** more than 100,000 consecutive losses in one chain still stop the direction (way out: delete the contact on both devices); a real gap heals only after the 10-minute wait, counted in one process lifetime (a restart starts it again). **Residual (MEDIUM in review, documented):** a relay that withholds the start of a run of more than 1,000 texts for longer than the wait can make them skipped: on the current chain they read `NotDelivered` once they arrive, on a chain the skip left they stay pending until cancelled; no code can tell this from a gap nothing fills (before, such a relay could stop the direction for good). **LOW:** forged far messages (anyone who can write to the mailbox; no session header needed) can hold a far skip back while the writer keeps doing it and up to the wait after; with the genuine chain's key (the relay's operator; anyone on V1) one can start that chain's wait early; a far try costs tens of milliseconds under the store lock (47–90 ms on one Xeon core, release; phones not measured), a timing hint next to R-9. **INFO:** a lost text of a chain a far skip left is not recognised; a crash between deleting a far candidate and its try loses that copy (sent again); three paths have no test (wait reset on session retire, continuing after a settle error, dropped on a non-Crypto far error). | `crates/core-crypto/src/ratchet.rs:51` (`MAX_FAR_SKIP`), `:264` (`decrypt_far`), `:277` (`needs_far_skip`), `:397` (`skip_message_keys`); `crates/core-crypto/src/ratchet/checkpoint.rs:766` (test, `MAX_RESUMABLE_NR`); `crates/core-protocol/src/durable.rs:752`; `crates/core-protocol/src/messaging.rs:437`, `:550`; `crates/mobile-ffi/src/messaging_api.rs:259`, `:273`; `crates/mobile-ffi/src/network.rs:304` (`FAR_TRIES_PER_ROUND`), `:315` (`FAR_SKIP_WAIT`), `:325` (`FAR_CHAINS_PER_SESSION`), `:1642` (`far_candidate`), `:1713` (`far_progress`), `:1730` (`far_pass`), `:819` (called after the message pass); ratchet tests `crates/core-crypto/src/ratchet.rs:1658, 1689, 1708, 1730, 1749, 1771, 1787`; network tests `crates/mobile-ffi/src/tests/far_skip.rs:50, 81, 124, 169, 236, 269, 300, 329, 383, 420, 444, 489`; `docs/NET-MESSAGING.md:212` (section 3), `:586-640` (section 8) | `SV`; `RUNTIME_VERIFIED` (tests on `main`'s code and with the fix, mutations; CI on `0392a57`); phones `NV` |
| **R-20** (cancelling more than `MAX_SKIP` encrypted texts in a row leaves a gap that stops the chain) | **PARTIAL.** The positions of cancelled texts are never sent, so their gap is one nothing fills: after the wait of R-14, a far skip crosses it, up to 100,000 positions (test `a_gap_of_more_than_max_skip_in_one_chain_is_crossed`, which fails on `main`'s code). **Remains:** a gap of more than 100,000 cancelled texts in a row; the first message after the gap arrives only after the wait. | as R-14; `crates/mobile-ffi/src/tests/far_skip.rs:50` | `SV`; `RUNTIME_VERIFIED` |

---

## Update 2026-11-18: X-6 fixed (`main` @ `f452eb3`)

**Snapshot:** `main` @ `f452eb3bf110022b7e4c8cd5aa586533774493ec` (the merge of PR #211). The fix was
asked for by the Owner on 2026-11-18 ("X-6") and merged on the Owner's instruction ("мёрдж #211").
Each `path:line` below was re-read at `f452eb3`.

**Runtime evidence.** PR #211: 18 check runs success on head `eaffc0c`. Two emulator jobs
first failed before any test ran, one on a Maven Central `429 Too Many Requests`, one on a
corrupt emulator package download; each passed on its single re-run. Locally `cargo test
--workspace --locked` → 620 passed, 0 failed. The new test fails with `main`'s rule restored.
One fresh-context review (`engineering-code-review`, `arcium-security-review`): no security
finding; its INFO notes were fixed in the PR. A review is analysis, not proof.

| ID | Status at `f452eb3` | Evidence (`main` @ `f452eb3`) | Label |
|----|---------------------|-------------------------------|-------|
| **X-6** (residual replay on the SPK-only path) | **FIXED.** A handshake that names no one-time prekey is refused with `OneTimePrekeyRequired` whether or not this device holds one, so the path without replay protection is closed. Every path that records a handshake or derives a session from one goes through `check_answerable` first (recording a provisional handshake, promotion on the first message, the record beside an own session, `beside_authenticates`), and the network layer answers the error with an R-1 refusal, so an initiator starts again. The path was unreachable in production (no record without a one-time prekey). **Scope:** the wire format keeps the form, and an initiator still builds it from a bundle without a one-time prekey (refused by the responder); `responder_session` still takes an optional one-time prekey, so a future caller that skipped `check_answerable` would reopen the path (INFO). | `crates/mobile-ffi/src/lib.rs:1031` (`check_answerable`), `:1046` (the refusal), `:964` (doc table), `:654` (refusal reason); test `crates/mobile-ffi/src/lib.rs:2402`; `docs/S2-B2-DURABLE-MESSAGING.md:280-289` (replay) | `SV`; `RUNTIME_VERIFIED` (test; CI on `eaffc0c`) |
| **R-6** (signed prekey never rotated) | Note only; status unchanged (**ACCEPTED**). The Owner's decision was to revisit it together with X-6; X-6 is now closed, so the revisit is due. Nothing was changed. | the R-6 row | `SV` |

---

## Update 2026-11-18: R-6 revisited (`main` @ `9b95493`)

**Snapshot:** `main` @ `9b9549390c32f8f0f699e36f0ef828a3ae0d7122` (the merge of PR #213). The
revisit was asked for by the Owner on 2026-11-18 ("R6"). The Owner decided to keep the signed
prekey unrotated and record why ("Не менять, записать"). A fresh review then found a case where
that was unsafe, and the Owner chose to replace the one-time prekey there ("Заменять одноразовый
ключ"). PR #213 was merged on the Owner's "Ok" to the request "мёрдж #213". Each `path:line`
below was re-read at `9b95493`.

**Runtime evidence.** PR #213: 18 check runs success on head `0947d82`, the Android emulator
jobs included. Locally `cargo test --workspace --locked` at `2abb1c5` → 625 passed, 0 failed;
the later commits changed one test line, docs and a doc comment. Six mutations, each removing
one guarded behaviour, each failed a test. Two fresh-context reviews (`engineering-code-review`,
`arcium-security-review`): the first found the simultaneous-start case (MEDIUM, confirmed at
runtime by a probe), which the PR fixes; the second found nothing above LOW. A review is
analysis, not proof.

| ID | Status at `9b95493` | Evidence (`main` @ `9b95493`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-6** (signed prekey never rotated) | **ACCEPTED (Owner decision reaffirmed 2026-11-18); one case fixed.** The signed prekey is still made once and kept for the life of the identity. Every answered handshake uses a one-time prekey (X-6); once that prekey is replaced, the identity, the signed prekey and the prekey record this device keeps no longer derive the keys of a first message under it, and the session stops using the signed prekey as its ratchet key at the first message. **Fixed:** at a simultaneous start, the contact's first message authenticates beside this device's own session with the one-time prekey only read; when the contact gave its session up and this device's session was confirmed, the prekey stayed, so a later leak of the store read the contact's given-up first messages. Now the confirming receive replaces that prekey in the same transaction that deletes the handshake beside the session, if the prekey record can still answer it. **Remains (documented, not fixed):** after a store leak, the next first contact under the one-time prekey held then can be read passively, however late it comes; so can first messages never accepted here while their one-time prekey stays published (withheld by the relay, from a contact deleted before they arrived or while a conflict was shown, beside a session this device gave up whose contact never sent them again). Rotating the signed prekey would bound that time. Whoever holds the identity secret can sign a signed prekey of their own; rotation does not stop that. **LOW (new, documented):** anyone who can write to the mailbox can put a handshake "from" a contact beside this device's own unconfirmed session; when the contact confirms it, the one-time prekey is replaced, so a third contact's first contact in flight under it is refused and its texts read `NotDelivered`; at most once per confirmation of an own session (before, consuming a prekey took a pinned contact's identity secret). **INFO:** no test covers a crash or an unknown commit outcome with the replacement installed, nor a two-process race on the prekey record (a generic stand-in hook is tested). | `crates/mobile-ffi/src/lib.rs:822-832` (reason on `establish_prekeys`), `:1189` (`replace_beside_prekey`), `:762` (installed), `:1042` (`check_answerable`); `crates/mobile-ffi/src/network.rs:741-743` (prekeys made only when absent); `crates/core-protocol/src/messaging.rs:101` (`with_beside_discard`), `:607-619` (committed with the discard); `crates/core-protocol/src/messaging/types.rs:127`; `crates/core-protocol/src/messaging/beside.rs:172`; tests `crates/mobile-ffi/src/lib.rs:2564, 2661, 2693`, `crates/core-protocol/src/messaging/tests/beside.rs:266, 328`, `crates/mobile-ffi/src/tests/chat.rs:394`; `docs/NET-MESSAGING.md:644` (mailbox writer), `:654` (rotation and what remains), `:796` (section 10); `docs/S2-B2-DURABLE-MESSAGING.md:251` | `SV`; `RUNTIME_VERIFIED` (tests, mutations; CI on `0947d82`); remains `INFERRED` |

---

## Update 2026-11-18: R-9 narrowed further (`main` @ `c2acfb6`)

**Snapshot:** `main` @ `c2acfb6957e17e2905c05c82a7877e4d19f823e1` (the merge of PR #215). The
fix was asked for by the Owner on 2026-11-18 ("R9"), who chose that the relay checks the sender
("Сервер проверяет отправителя"), and merged on the Owner's "Мерж" to the request "мёрдж #215".
Each `path:line` below was re-read at `c2acfb6`.

**Runtime evidence.** PR #215: 18 check runs success on head `3e6f184`, the Android emulator
jobs (`connected-tests`, `two-devices`, which run over a V2 relay) included. Locally `cargo test
--workspace --locked` at `168c5e2` → 628 passed, 0 failed; at `3e6f184` the relay tests →
`test result: ok. 62 passed; 0 failed` and `tests::relay_v2` → `test result: ok. 8 passed; 0
failed`. Three mutations of the SEND rule (open as before, AUTH without the sender check, SEND
without AUTH), each failed relay and app tests. One fresh-context review
(`engineering-code-review`, `arcium-security-review`): nothing above LOW; its LOW items (stale
comments and texts) were fixed in the PR. A review is analysis, not proof.

| ID | Status at `c2acfb6` | Evidence (`main` @ `c2acfb6`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-9** (a reader of a mailbox learns whom its owner has pinned) | **OPEN — narrowed further.** **Closed for everyone but the relay's operator on V2:** a V2 relay stores a SEND only on a connection with a valid AUTH, and only for an envelope whose sender field (bytes 5..37, the sender of `ENVELOPE_V1`) is the authenticated owner; anything else is answered UNAUTHORIZED before the mailbox is looked at (no FULL, no duplicate sequence number), and nothing is stored. So no one else can plant messages or handshakes "from" a pinned contact X to count the places they take, or to draw a refusal that shows X is pinned (the probe of the #181 review). The app already sent every envelope as itself on its authenticated round connection; first contact is unchanged (the initiator authenticates as itself). **Remains:** the relay's operator reads every mailbox and can store an envelope naming any sender; V1 (development builds) checks nothing; any key may authenticate as itself and count a mailbox's free places (how many envelopes wait, visible because it fills the mailbox) or send one stored envelope again (its stored sequence number while it is there: whether the owner kept that sender's own message, and when the owner's rounds run) — that shows whether the owner pinned that sender and has no session with it yet, which a real handshake shows as well. Keep-versus-delete itself is unchanged. The relay is not deployed yet; one built before this change accepts unauthenticated SENDs. **Also narrowed:** findings and residuals that assumed anyone can write "from" a contact (forged handshakes of R-13, the mailbox-writer LOW of R-6, forged far messages of R-14) now need, on V2, the relay's operator or the contact's identity secret (`docs/NET-MESSAGING.md` section 3, "mailbox writer"). | `Session::screen` (`crates/relay/src/server.rs:544`, SEND at `:548`); `ENVELOPE_SENDER` (`crates/relay/src/protocol.rs:102`, rule `:80`); app sends only on `connect_owner` (`crates/mobile-ffi/src/network.rs:668`; `connect` `:653`; `send_to` `:1037`); tests `crates/relay/src/v2_tests.rs:167` (`without_auth_only_get_bundle_is_answered`), `:190` (`a_send_is_stored_only_for_an_envelope_naming_the_authenticated_owner`), `crates/mobile-ffi/src/tests/relay_v2.rs:147` (`a_v2_relay_refuses_an_envelope_that_names_another_sender`), `crates/mobile-ffi/src/network/wire.rs:255` (envelope layout tied to `ENVELOPE_SENDER`); `docs/NET-MESSAGING.md:111-116` (V2 rule), `:150` (mailbox writer), `:552` (section 8); `docs/RELAY-PRODUCTION-DESIGN.md:81` (amended design) *(Note 2026-11-21: the `network.rs` anchors here moved in PR #242; see "Update 2026-11-21: code locations after the split". Status unchanged.)* | `SV`; `RUNTIME_VERIFIED` (tests, mutations; CI on `3e6f184`); remains `INFERRED` |

---

## Update 2026-11-19: option B, R-21, H-6, R-24, R-22 (`main` @ `8bac3f3`)

**Snapshot:** `main` @ `8bac3f3c982f611e818960546d4aba68f718ab86` (the merge of PR #220). Asked for by the Owner on 2026-11-18
("Делаем всё попорядку": option B, R-21 older chains, then R-24, R-22, H-6/H-7). The Owner
answered the design questions on 2026-11-18 (only the user starts a reset; both resetting at once is
the existing conflict; remember four older chains, checkpoint V2) and on 2026-11-19 chose to merge
all four PRs in order ("Все четыре по порядку") and to rotate the signed prekey as a separate task
("Да, отдельной задачей"). Merged with normal merge commits pinned with `expectedHeadSha`: #217 as
`1cca4b8`, #218 as `d983e8e`, #219 as `d1d2cde`, #220 as `8bac3f3`. Each `path:line` below was re-read
at `8bac3f3`.

**Runtime evidence.** Locally, on the tree of `8bac3f3`: `cargo test --workspace --locked` →
660 passed, 0 failed (`core-crypto`: `test result: ok. 135 passed; 0 failed`; `core-protocol`: `test result: ok. 149 passed; 0 failed`; `mobile-ffi`: `test result: ok. 257 passed; 0 failed; 1 ignored`), and `cargo clippy --workspace --locked -- -D warnings` passes. CI: every check run success on each PR's merged head (#217 `068d207`, 19 runs; #218
`10667b2`; #219 `a1dda2f`, 19 runs; #220 `2fb7b14`, 19 runs, after one re-run: Maven Central answered the Android dependency download with HTTP 429). Mutations, each caught by a test: about 25 for
#217 across five rounds, 7 for #218, 1 for #219, 3 for #220. Fresh-context reviews: five rounds for
#217 (two HIGHs and two MEDIUMs found and fixed, the key-compromise MEDIUM documented, the last
round nothing above INFO), two for #218 and one for #219/#220 (nothing above LOW; LOWs fixed). A
review is analysis, not proof.

| ID | Status at `8bac3f3` | Evidence (`main` @ `8bac3f3`) | Label |
|----|-------------------|-----------------------------|-------|
| **R-13** (a false conflict dead-ends the conversation) | **PARTIAL — a way out by a reset (option B).** The dead end that remains after resolving a false conflict is ended by a reset on the waiting device, the one that resolved (`reset_session`, works offline, also with no session): it gives its texts up (`NotDelivered`) and starts a new session, and the other device replaces its established session once the first message under the new handshake authenticates there. A reset on the other device should end it as well, since the waiting device accepts the contact's next handshake (`INFERRED`, no test). With option B on both devices no out-of-band coordination is needed; deleting the contact on both devices stays a way out too. The replay residual is narrowed further: every confirmation of an own session now replaces the one-time prekey, and a store written before option B replaces it once on the first round, so a captured genuine handshake can be answered only until the prekey next changes. **Remains:** a replayed genuine handshake and first message can still raise a false conflict while this device's own session is unconfirmed and the one-time prekey they name is still the published one; nothing ends a dead end by itself (the user resets); the contact's device must run a build with option B, or the restart waits until it updates (`docs/NET-MESSAGING.md:905`); after a reset `NotDelivered` means "given up", not "never read" (`:955`). Both users resetting at once is the conflict of option A, resolved by the greater key. | `reset_session` (`crates/mobile-ffi/src/network/chat.rs:921`), `accept_restart` (`:1156`); the restart check (`crates/mobile-ffi/src/network.rs:1254`); `replace_prekey_on_confirm` (`crates/mobile-ffi/src/lib.rs:1272`), `replace_prekey_once` (`:1379`); tests `tests::restart` (`a_reset_ends_the_dead_end_of_a_false_conflict`, `both_resetting_at_once_is_a_conflict_the_greater_key_resolves`, `a_handshake_from_before_the_upgrade_is_refused_in_the_first_upgraded_round`); `docs/NET-MESSAGING.md:898` *(Note 2026-11-21: the `lib.rs` and `network.rs` anchors here moved in PRs #241 and #242; see "Update 2026-11-21: code locations after the split". Status unchanged.)* | `SV`; `RUNTIME_VERIFIED` (tests, mutations, CI) |
| **R-6** (signed prekey never rotated) | **OPEN — reopened (Owner decision 2026-11-19).** Option B accepts a restart authenticated by X3DH alone, so this device's signed-prekey secret, which is never rotated and lives in its store, lets whoever copied the store and can write the mailbox (on V2 the relay's operator, on V1 anyone) replace any established session at any later time and then read and write it as the contact (key-compromise impersonation: X3DH's first DH is `DH(signed prekey, contact's identity key)`). The contact's identity secret does the same. Before option B such a compromise could not replace an existing session and healed with the ratchet; now the only sign is the `peer_reset` notice. Confirmed at runtime by a review probe (not committed). The reason R-6 was accepted ("a leak of it is a leak of all of them") no longer bounds how long the damage lasts. The Owner chose rotation as a separate task. Severity: MEDIUM in review (the LOW of the 2026-11-12 row predates option B). The LOW of the 2026-11-18 row no longer needs a mailbox writer: every confirmation of an own session now replaces the one-time prekey (`replace_prekey_on_confirm`, `crates/mobile-ffi/src/lib.rs:1272`), so another contact's first contact or a contact's restart in flight under it is refused once and made again, its texts `NotDelivered` (`docs/NET-MESSAGING.md:702`). | the restart check (`crates/mobile-ffi/src/network.rs:1254`); `x3dh_respond` DH1 (`crates/core-crypto/src/x3dh.rs:186`); `docs/NET-MESSAGING.md:708`; `docs/SESSION-RECOVERY-OPTIONS.md` (option B) | `SV`; `RUNTIME_VERIFIED` (review probe); rotation `NOT_VERIFIED` (not built) |
| **R-21** (a late message whose skipped key was evicted is lost, and its sender keeps resending it) | **PARTIAL — narrowed further.** The ratchet remembers the last `MAX_PREV_CHAINS` (4) receiving chains it left (the peer's ratchet key and the position the chain ended at, `header.pn` at the DH step), rolled back with the rest of the state on a failed decrypt and kept in `RATCHET_STATE_V2` (V1 still read, as no history). A late message of one of those chains whose key is gone is named back with GONE, as for the current chain, and a header of a remembered chain never takes a far try. **Remains:** a late message of a chain left more than four steps ago is deleted silently and its sender keeps it pending until the user cancels it; a session stored as V1 starts with no history; an older build refuses a V2 record, so going back is not supported. | `MAX_PREV_CHAINS` (`crates/core-crypto/src/ratchet.rs:58`), `needs_far_skip` (`:315`), `is_beyond_recall` (`:399`), `leave_chain` (`:416`); `check_chains` (`crates/core-crypto/src/ratchet/checkpoint.rs:459`); tests `ratchet.rs:1804`, `crates/mobile-ffi/src/tests/beyond_recall.rs:141` | `SV`; `RUNTIME_VERIFIED` (tests, mutations, CI) |
| **R-14** (more than `MAX_SKIP` lost messages stop a direction) | Note only; status unchanged (**PARTIAL**). With R-21 above, both its MEDIUM residual (texts a withholding relay made skipped on a chain the skip left stay pending until cancelled) and its INFO (a lost text of a chain a far skip left is not recognised) now hold only for a chain left more than four steps ago; on one of the last four such texts are named back and read `NotDelivered` (`docs/NET-MESSAGING.md:671-678`). | as R-21 | `SV` |
| **R-22** (`last_sent` only grows) | **FIXED — the remaining cost too.** `prune_sent` lists the outbox's key names once (`Messenger::pending_outgoing_ids`) instead of reading and decrypting every session's outbox records each round; the set it keeps contains every id the old code kept. **INFO** as before (the same store error can be reported twice; a corrupt stored handshake of a confirmed session makes the prune fail each round; the guard for parallel rounds has no test). | `prune_sent` (`crates/mobile-ffi/src/network.rs:992`); `pending_outgoing_ids` (`crates/core-protocol/src/messaging.rs:688`); test `crates/core-protocol/src/messaging/tests.rs:208`; the `net_limits` prune tests | `SV`; `RUNTIME_VERIFIED` (tests, mutations); cost on a phone `NV` |
| **R-24** (X3DH accepted low-order peer keys) | **FIXED — remainder (a) too.** `add_contact` refuses a card whose X25519 identity key has low order (`InvalidContactCard`); a card an older build pinned still decodes, but adding it again is refused. **Remains (INFO):** (b) a provisional handshake with a low-order key recorded by an older build, unchanged. | `crates/mobile-ffi/src/contacts.rs:109`; `has_low_order` (`crates/mobile-ffi/src/lib.rs:680`); test `lib.rs:2405` | `SV`; `RUNTIME_VERIFIED` (tests, mutation) |
| **H-6** (stale key copies in the skipped-key `IndexMap`) | **OPEN — narrowed further.** After a late read takes a key with `shift_remove`, a placeholder entry is pushed and popped over the slot past the last entry, so it no longer holds a copy of the last key (best effort: skipped when the placeholder's key is stored or the map reports no room; the index table can run out of growth first). A probe reading that slot (not committed: it reads past the map's length) showed the last key there before and zeroes after, in debug and release. **Remaining:** copies of key bytes outside the map (stack, AEAD); the overwrite relies on indexmap 2.x internals that no test pins. | `overwrite_spare_slot` (`crates/core-crypto/src/ratchet.rs:87`); test `ratchet.rs:1506` | `SV`; `RUNTIME_VERIFIED` (probe, tests, mutation); freed memory on a phone `NV` |
| **H-7** (copies of secret arrays are not wiped) | Note only; status unchanged (**OPEN — narrowed**). No code change: the remaining by-value copy in `StaticSecret::from([u8; 32])` cannot be removed without `unsafe` or an upstream API, and `StaticSecret::random_from_rng` fills an unwiped local array that it moves into the secret (source; whether a copy is left in memory is `INFERRED`, see H-8). | as in the 2026-11-15 update | `SV` |

**Also merged with #217:** `ArciumCore::retire_session` had been inside a `uniffi::export` block, which
exported it to Kotlin although documented as internal; it was moved before the merge, and the source
check of exported outbox removals now covers it (`crates/mobile-ffi/src/tests/ack_probe.rs:223`).

---

## Update 2026-11-19: R-6 signed prekey rotated (`main` @ `553c3ba`)

**Snapshot:** `main` @ `553c3ba59434ae9ecd9c4c8fb0495bc0b9a88f8d` (the merge of PR #222, head `b6c96cb`).
The Owner reopened R-6 as a separate task on 2026-11-19 ("Да, отдельной задачей"), approved the
design as written ("Одобряю как есть"), chose the period ("7 дней") and accepted the device-clock
risk, to be documented and reconsidered at the security audit ("Принять и описать"); the merge was
on the Owner's answer "Мёрдж #222". Normal merge commit pinned with `expectedHeadSha`. Each
`path:line` below was re-read at `553c3ba`.

**Runtime evidence.** Locally, on `a38f1ce` (the head's last commit `b6c96cb` changes only comments and
documentation): `cargo test --workspace --locked` → `core-crypto`: `test result: ok. 135 passed; 0 failed`;
`core-protocol`: `test result: ok. 149 passed; 0 failed`; `mobile-ffi`: `test result: ok. 284 passed; 0 failed; 1 ignored`;
`cargo clippy --workspace --locked -- -D warnings` passes (also with `-p mobile-ffi --all-targets` on
`b6c96cb`). CI on `b6c96cb`: 18 check runs, all success, including the emulator jobs. 18 mutations, each
caught by a test. Three fresh-context review rounds (crypto/protocol, durable state, network,
engineering; findings adversarially verified): nothing above LOW; every LOW fixed before the merge. A
review is analysis, not proof.

| ID | Status at `553c3ba` | Evidence (`main` @ `553c3ba`) | Label |
|----|-------------------|-----------------------------|-------|
| **R-6** (signed prekey never rotated) | **PARTIAL — rotated; the key-compromise route bounded.** **Fixed:** the signed prekey is checked at the start of every round, before the bundle is published and before the mailbox is read, and rotated when due: (E) at the first round after the one-time prekey changed, with no previous key kept; (T) 7 days after the relay first accepted it, by this device's clock in either direction, with the old one kept as the previous key for one more period. A key the relay never accepted does not age. The previous key answers a handshake only together with the one-time prekey it was published with, and every write that replaces the one-time prekey drops it. So a copy of the store replaces an established session (option B), or makes a first contact "from" a pinned contact, only while the copied signed prekey is still held: until the first round after a one-time-prekey change, at the latest about two periods (14 days) of rounds that publish the bundle; and, with one instance on the database, at most once (the accepted forgery consumes the one-time prekey and the previous key, and the next round rotates before a new one-time prekey is published). A conflict beside an own unconfirmed session can still be raised within that time, more than once (that check only reads). Passive reading of later first messages from a copy is bounded the same way. A V2 record (138 bytes) is read in place and rotated at the first round; the record is written as V3 (186 bytes) under the same key. **Remains:** the identity secret is in the same store, and its holder can sign signed prekeys of its own, impersonate this device to its contacts and restart its sessions there, for as long as the identity is used (rotation does not stop that); malware with lasting access gets every new key; a rollback of the store (D-009) brings old keys back until they are rotated out (a restored key due by time stays about one more period as the previous key); a relay that refuses or cuts the bundle's publication delays the removal of the copied key (a key ages only once the relay accepted it) for as long as it does so, while every round of the device fails before the mailbox; the device clock (**ACCEPTED**, Owner 2026-11-19: a frozen or attacker-held clock stops rotation by time; a step back delays it, which lengthens the window of a copy; a jump of a period rotates early and drops the older previous key early); on disk, whether `secure_delete` overwrites the old cell on an update and what the rollback journal leaves are not shown; a replaced secret is wiped on drop, read from source and not observed on a device (H-8), and moves of secrets can leave stack copies (H-7); a responder session an older build stored at generation 0 keeps the signed prekey of its time in its ratchet until its first message (it no longer answers a handshake). **INFO:** the bundle now changes about once a week while the device is online, and `GET_BUNDLE` needs no authentication, so whoever knows the device's key can learn roughly when it ran its first round after each 7-day mark. **INFO:** with two instances on one database, a promotion that commits between one instance's maintenance read and its export makes the published bundle pair the current signed prekey with the new one-time prekey: until the next round rotates, a handshake under that pair is answered (so a copy holding the current key could replace a second session), and one read after that rotation is refused once and made again. Production runs one sync loop; the tests use two instances in one process for creation and rotation only, and none runs this interleaving. **Cost (documented):** an initiator delayed by more than about one period between fetching the bundle and this device reading its handshake, or a conflict left unresolved that long, is refused and starts again, and its texts read `NotDelivered`. Going back to an earlier build is not supported (it fails closed at the bundle export). | the record and the rule: `PREKEY_RECORD_V3_LEN` (`crates/mobile-ffi/src/lib.rs:429`), `SIGNED_PREKEY_PERIOD_SECS` (`:444`), `renew_one_time_prekey` (`:546`), `unpack_prekeys` (`:593`), `plan_rotation` (`:695`), `rotate_signed_prekey` (`:713`), `check_answerable` (`:1339`), `accept_first_message` (`:1415`), `replace_prekey_on_confirm` (`:1521`), `maintain_prekeys` (`:1672`), `note_prekeys_published` (`:1716`); the round: `put_bundle` (`crates/mobile-ffi/src/network.rs:748`), called before the mailbox at `:806`, the clock `this_second` (`:1971`); tests `crates/mobile-ffi/src/tests/prekey_record.rs` (16), `crates/mobile-ffi/src/tests/spk_rotation.rs` (9; the regression `a_copied_store_cannot_replace_a_session_once_its_signed_prekey_is_gone` `:402`, `a_copied_store_replaces_at_most_one_session` `:465`, the round guard `:361`, `:513`), `tests::legacy_upgrade::a_v2_prekey_record_is_rotated_on_the_first_round`, `tests::network_crash::a_device_killed_around_a_rotation_rotates_once_and_answers_the_served_bundle`; `docs/NET-MESSAGING.md:437` (section 6), `:738` (the bounded route), `:794` (rotation and what remains), `:836` (clocks), `:857` (the weekly bundle change) *(Note 2026-11-21: the `lib.rs` and `network.rs` anchors here moved in PRs #241 and #242; see "Update 2026-11-21: code locations after the split". Status unchanged.)* | `SV`; `RUNTIME_VERIFIED` (tests, mutations, CI); the bounds `INFERRED` from the code and the regression test; two processes, device clocks and on-disk remnants `NOT_VERIFIED` |

The review checklist (`.claude/skills/arcium-security-review/references/threat-checklist.md`) no longer
says the signed prekey is not rotated; its X3DH and option-B items now ask for the rotation rules.

---

## Update 2026-11-19: R-21 32 chains, R-14 wait kept across restarts (`main` @ `2a6074f`)

**Snapshot:** `main` @ `2a6074fd39e33a0f814a49a7118ee8b5f2abe3e6` (the merge of PR #227, head `a4a9ebc`;
PR #226 merged before it as `b476035`, head `0100df0`). Asked for by the Owner on 2026-11-19 ("Давай
остатки протокола: R-9, R-14, R-21"), who chose to remember 32 earlier receiving chains ("32 цепочки"),
to keep the far-skip wait in the store by the device clock ("Хранить в базе"), and first to delete a
message with no session whatever its sender, then to defer that change ("Отложить R-9"). The merges
were on the Owner's messages "Мёрдж #226" and "Мёрдж #227". Normal merge commits pinned with
`expectedHeadSha`. Each `path:line` below was re-read at `2a6074f`.

**Runtime evidence.** Locally, on `a4a9ebc` (the same tree as `2a6074f`): `cargo test --workspace --locked`
→ `core-crypto`: `test result: ok. 135 passed; 0 failed`; `core-protocol`: `test result: ok. 149 passed; 0 failed`;
`mobile-ffi`: `test result: ok. 300 passed; 0 failed; 1 ignored`; `relay`: `test result: ok. 62 passed; 0 failed`; every other test binary `0 failed`;
`cargo clippy --workspace --locked -- -D warnings` passes (also `-p mobile-ffi -p core-crypto --all-targets`).
CI: 18 check runs, all success, on each merged head (#226 `0100df0`, #227 `a4a9ebc`), including the
emulator jobs. Mutations, each caught by a named test: 3 for #226, 21 for #227. Fresh-context reviews:
one for #226 (nothing at LOW or above), two for #227 (nothing at MEDIUM or above; two LOW kept as
documented residuals, below). A review is analysis, not proof.

| ID | Status at `2a6074f` | Evidence (`main` @ `2a6074f`) | Label |
|----|-------------------|-----------------------------|-------|
| **R-21** (a late message whose skipped key was evicted is lost, and its sender keeps resending it) | **PARTIAL — narrowed further.** The ratchet now remembers the last `MAX_PREV_CHAINS` = 32 receiving chains it left (4 before). One is left per exchange, so a late message of about the last 32 exchanges whose key is gone is named back with GONE and its text reads `NotDelivered` at the sender (a text still pending there, on a build that acts on GONE). Each remembered chain is 36 bytes of public data; `RATCHET_CHECKPOINT_MAX_LEN` is now 137,335 bytes. The record format is unchanged (`RATCHET_STATE_V2`); only its limit moved. **Remains:** a late message of a chain left more than 32 steps ago is deleted silently and its sender keeps it pending until the user cancels it; a session stored as V1 starts with no history. Going back is not supported: a build that remembers at most 4 refuses a record holding more (`TooManyChains`), so after about five exchanges in any session its rounds fail for every contact. | `MAX_PREV_CHAINS` (`crates/core-crypto/src/ratchet.rs:62`), `is_beyond_recall` (`:403`), `leave_chain` (`:420`); `RATCHET_CHECKPOINT_MAX_LEN` (`crates/core-crypto/src/ratchet/checkpoint.rs:130`), `check_chains` (`:459`); tests `ratchet.rs:1808`, `checkpoint.rs:551`, `:637`, `:791`, `crates/mobile-ffi/src/tests/beyond_recall.rs:348` (uses the literal 32); `docs/S2-B2-DURABLE-MESSAGING.md:630` (going back) | `SV`; `RUNTIME_VERIFIED` (tests, mutations, CI); going back `INFERRED` from the earlier build's code (not run) |
| **R-14** (more than `MAX_SKIP` lost messages stop a direction) | **PARTIAL — narrowed.** **Fixed:** the wait before a far skip no longer starts again when the app restarts, unless the write of its start failed (reported; that chain then waits again after a restart). It is kept in the local record `farwait:v1/<handle>` (per chain, the ratchet key a far message named and when one was first and last seen, in milliseconds of this device's clock; at most `FAR_CHAINS_PER_SESSION` (4) chains), and read back by a new process (the tests stand in with a new instance on the same database in one process). The record is deleted when the session accepts a message, when the network layer gives the session up (a reset, a restart by the contact, an own unconfirmed session given up), and with the contact in the forget transaction. A record that does not parse or decrypt is read as no wait and replaced; if the store cannot be read, that session tries no far skip in the round and the error is reported. The three paths the review of PR #209 found untested now have tests (the wait forgotten on a reset; a far try failing other than by not decrypting; a failed settle after a far skip). **Remains:** more than 100,000 consecutive losses in one chain still stop the direction; the way out is now a reset of the session on either device, with option B in both devices' builds (`INFERRED` from the reset path, which does not depend on the gap; no test resets a session after more than 100,000 losses: the ratchet test `a_far_skip_reaches_max_far_skip_and_no_further`, `crates/core-crypto/src/ratchet.rs:1914`, shows only that a far skip of 100,000 works and one more is refused), or deleting the contact on both devices. The wait follows the device's wall clock (Owner, 2026-11-19, as for R-6): a step forward shortens it (so does a clock set back before the first sighting and then corrected), a step back lengthens it, a reading before the first sighting starts it again, a frozen or attacker-held clock holds the far skip back for as long as it stays so, and it also counts while the app is not running. The MEDIUM residual of the 2026-11-18 row (a relay that withholds the start of a run for longer than the wait) is unchanged in kind; since the wait now goes on across restarts, the withholding no longer has to last through one lifetime of the receiving process (`INFERRED`). With R-21 above, texts it made skipped on a chain the skip left stay pending only for a chain left more than 32 steps ago; likewise its INFO (a lost text of a chain a far skip left is not recognised) now holds only for a chain left more than 32 steps ago. **LOW (new, documented):** the record is deleted in its own write after an accepted message and after the session is given up, not in the same transaction; a process death just before that write, or a failed delete (reported in the round's errors only after an accepted message; after a give-up it is ignored), leaves the record, so a later far message of a chain it names may be tried without the full wait (after a give-up it names only the old session's chains, and the next session's first accepted message deletes it); the exported `remove_session` does not delete it either, nor does a build before this change, so going back and forward again can leave one too (`docs/S2-B2-DURABLE-MESSAGING.md:653`). **LOW (new, documented, next to R-9):** the first far message of a chain costs a store write in that round, which a far message "from" a stranger does not, so a mailbox writer who can time the round (on V2 the relay's operator) can tell a contact with a session from a stranger in the first round, without the wait. **Not tested:** store faults (a failed read, write or delete, a poisoned lock), a record that fails to decrypt, a process death between an accepted message and the delete, and the delete when a restart by the contact or an own unconfirmed session given up retires the session (only a reset is tested; all three go through `retire_session_texts`). | `far_wait_key` (`crates/mobile-ffi/src/network.rs:295`), `pack_far_waits` (`:310`), `unpack_far_waits` (`:324`), `note_far_sighting` (`:361`), `FAR_SKIP_WAIT` (`:430`), `FAR_CHAINS_PER_SESSION` (`:440`), `far_candidate` (`:1883`), `forget_far_waits` (`:1941`), `stored_far_waits` (`:1962`), `store_far_waits` (`:1991`), `far_progress` (`:2026`), `far_pass` (`:2047`), `this_millis` (`:2170`); the deletes in `crates/mobile-ffi/src/network/chat.rs:988` (`delete_contact`) and `:1250` (`retire_session_texts`); tests `crates/mobile-ffi/src/tests/far_skip.rs:553` (`the_wait_goes_on_across_a_restart`), `:588`, `:636`, `:657`, `:693`, `:737`, `:776`, `:450`, and the unit tests in `network.rs:2281`; `docs/NET-MESSAGING.md:261` (the way out), `:265` (the record), `:727` (the timing signal), `:742` (the clock); `docs/S2-B2-DURABLE-MESSAGING.md:651` *(Note 2026-11-21: the `network.rs` anchors here moved in PR #242; see "Update 2026-11-21: code locations after the split". Status unchanged.)* *(Note 2026-11-22: a process death in the far pass now has a test; see "Update 2026-11-22: process-kill tests inside a round". Status unchanged.)* | `SV`; `RUNTIME_VERIFIED` (tests, mutations, CI); the way out past 100,000 `INFERRED`; store faults, device clocks, a real process restart and phones `NOT_VERIFIED` |
| **R-20** (cancelling more than `MAX_SKIP` encrypted texts in a row leaves a gap that stops the chain) | **PARTIAL — narrowed with R-14.** The first message after a gap of cancelled texts is read once the wait of R-14 has passed since its chain was first seen, now also across restarts of the receiving app. **Remains:** a gap of more than 100,000 cancelled texts in a row (way out as for R-14). | as R-14 *(Note 2026-11-21: R-14's anchors, its evidence, moved in PR #242; see "Update 2026-11-21: code locations after the split". Status unchanged.)* | `SV`; `RUNTIME_VERIFIED` |
| **R-9** (a reader of a mailbox learns whom its owner has pinned) | Note only; status unchanged (**OPEN — narrowed further**). The Owner first chose (2026-11-19) to delete a message with no session whatever its sender, so that keeping or deleting it no longer shows whom the owner pinned, and then deferred that change ("Отложить R-9"), to be reconsidered with the relay deployment: a probe (not committed) showed that it fails 11 existing tests, the mailbox-paging tests build their scenarios from those kept messages, and a message ahead of a late handshake would then wait for the sender's retransmission. Keep-versus-delete is unchanged. A new timing signal next to R-9 is recorded under R-14 above (LOW). | `docs/NET-MESSAGING.md:727`; the decision: continuity record D-064 | `SV` (no code change); the probe `RUNTIME_VERIFIED` by the author, not committed |

---

## Update 2026-11-20: R-21 beyond 32 chains (`main` @ `7b6677f`)

**Snapshot:** `main` @ `7b6677f7d62eb2eefd5f0bf17ef9522253cee61d` (the merge of PR #230, head `f4aa1ad`). Asked for by the Owner on
2026-11-20 ("А вот это можно сделать"), who chose, of three designs, to name a late message of a chain
the session no longer knows ("Незнакомая цепочка → GONE"). The merge was on the Owner's message
"Мёрдж #230". Normal merge commit pinned with `expectedHeadSha`. Each `path:line` below was re-read
at `7b6677f`.

**Runtime evidence.** Locally, on `f4aa1ad` (the same tree as `7b6677f`): `cargo test --workspace --locked`
→ `core-crypto`: `test result: ok. 136 passed; 0 failed`; `core-protocol`: `test result: ok. 149 passed; 0 failed`;
`mobile-ffi`: `test result: ok. 306 passed; 0 failed; 1 ignored`; `relay`: `test result: ok. 62 passed; 0 failed`; every other test binary `0 failed`;
`cargo clippy --workspace --locked -- -D warnings` passes (also `-p mobile-ffi -p core-crypto -p core-protocol --all-targets`).
CI: 18 check runs, all success, on the merged head `f4aa1ad`, including the emulator jobs. Mutations: 23
across the PR's three commits, each caught by a named test. Fresh-context reviews: two (nothing above
LOW; the three LOW they found were fixed before the merge). A review is analysis, not proof.

| ID | Status at `7b6677f` | Evidence (`main` @ `7b6677f`) | Label |
|----|-------------------|-----------------------------|-------|
| **R-21** (a late message whose skipped key was evicted is lost, and its sender keeps resending it) | **PARTIAL — narrowed further.** **Fixed:** once a session has received from the contact, a message that does not decrypt and whose header names a chain the session no longer knows (neither the current one nor one of the 32 remembered), with no key stored for its position and no far skip needed to reach it, is named back with GONE on its second arrival, and its text reads `NotDelivered` at the sender (a text still pending there, on a build that acts on GONE). A message of the contact's next chain decrypts unless the two sessions diverged (a rollback, a copied store), so a genuine message of that kind belongs to a chain left more than 32 exchanges ago, to a time before the session kept a history (`RATCHET_STATE_V1`), to another session of the contact, or to a session state that diverged from this one; none can be read here. Before, it was deleted silently. First arrivals are noted in memory, at most `FORGOTTEN_SEEN_PER_SESSION` (256) per session, the least recently seen dropped first; a named message stays noted, so its next arrival is named again (at most one GONE a minute per set of ids, as before); the notes are cleared when the contact is deleted or the session given up, and a restart of this device forgets them. The second-arrival rule is meant to keep two devices whose sessions diverged from naming each other's GONE messages round after round (`INFERRED` from the source; the test stands in with forged messages, no test uses two diverged devices). No record, wire, key or KDF change. **Remains:** a late message more than `MAX_SKIP` (1,000) positions into a forgotten chain, or with a `pn` more than 1,000 past the current chain's position, still needs a far skip, is not named, and its sender keeps it pending until the user cancels it; after a restart of this device a message of a forgotten chain needs two arrivals again (the notes are in memory only); a mailbox writer who sends 256 or more forged messages of that kind between two arrivals of a genuine one pushes its note out, and can fill the 256 places of a round's GONE, now without having seen a header of the session (an unknown key sent twice is enough), on V2 also with the contact's identity secret; before the session has received from the contact nothing of this kind is named. Going back to a build that remembers at most 4 chains is unchanged (not supported, as in the 2026-11-19 row). **Not tested:** a round that fails between noting and committing a GONE (the note survives it, `SV`); the `pn`-far branch of the exclusion on a forgotten chain; the rule on a session stored as V1; two diverged devices; a restart forgetting the notes. | `names_forgotten_chain` (`crates/core-crypto/src/ratchet.rs:434`), `is_beyond_recall` (`:407`), `MAX_PREV_CHAINS` (`:65`); `Recall` (`crates/core-protocol/src/messaging/types.rs:86`), `beyond_recall` (`crates/core-protocol/src/messaging.rs:435`), `DurableSession::names_forgotten_chain` (`crates/core-protocol/src/durable.rs:705`); `FORGOTTEN_SEEN_PER_SESSION` (`crates/mobile-ffi/src/network.rs:460`), the decision (`:1504`), `seen_again` (`:1669`), `forget_forgotten_notes` (`:1691`), `name_gone` (`:2170`); the clears in `crates/mobile-ffi/src/network/chat.rs:1013` (`delete_contact`) and `:1252` (`retire_session_texts`); tests `ratchet.rs:1898` (`a_header_of_a_forgotten_chain_is_named`), `crates/mobile-ffi/src/tests/beyond_recall.rs:350` (32 turns, then `ForgottenChain`), `:391` (end to end), `:479` (not before the session received), `:531` (256 notes), `crates/mobile-ffi/src/tests/restart.rs:868`, `crates/mobile-ffi/src/tests/delete_contact.rs:400`, `crates/mobile-ffi/src/tests/far_skip.rs:800` (a far message in its wait draws no GONE); `docs/NET-MESSAGING.md:341` (the rule), `:682` (what remains); going back `docs/S2-B2-DURABLE-MESSAGING.md:630` *(Note 2026-11-21: the `network.rs` anchors here moved in PR #242; see "Update 2026-11-21: code locations after the split". Status unchanged.)* *(Note 2026-11-22: the sender's side of a GONE message now has a process-kill test; see "Update 2026-11-22: process-kill tests inside a round". Status unchanged.)* | `SV`; `RUNTIME_VERIFIED` (tests, mutations, CI); the diverged-devices claim `INFERRED`; the untested paths `SV` only; phones `NOT_VERIFIED` |
| **R-14** (more than `MAX_SKIP` lost messages stop a direction) | Note only; status unchanged (**PARTIAL**). Its MEDIUM residual (texts a withholding relay made skipped on a chain the far skip left) and its INFO (a lost text of a chain a far skip left) narrow with R-21 above: such texts are now named back also once that chain is no longer among the last 32, on their second arrival, unless reaching them would need a far skip (then they stay pending until the user cancels them). | `docs/NET-MESSAGING.md:768` (a relay that withholds), `:796` (a text lost before a far skip's kept keys) | `SV` (docs and the R-21 code above) |
| **R-9** (a reader of a mailbox learns whom its owner has pinned) | Note only; status unchanged (**OPEN — narrowed further**). An accepted exception (Owner, 2026-11-20, with R-21 above): a message whose header names a chain a session that has received no longer knows draws a GONE on its second arrival, so whoever can put a forged message of that kind in the mailbox twice (on V2 the relay's operator or whoever holds the contact's identity secret; anyone on V1) learns that this device has a confirmed session with that contact. On V2 the relay's operator sees that session's envelopes anyway. | `docs/NET-MESSAGING.md:699` ("Naming against a mailbox writer"); `.claude/skills/arcium-security-review/references/threat-checklist.md:252`; test `crates/mobile-ffi/src/tests/beyond_recall.rs:479` (a forged one named on its second arrival once the session is confirmed, not before) | `SV`; `RUNTIME_VERIFIED` (the test) |

---

## Update 2026-11-20: core-transport not a mobile-ffi dependency (`main` @ `6dd93b2`)

**Snapshot:** `main` @ `6dd93b28af19234655cff041ee97298cbdebdd39` (the merge of PR #235). The change
is PR #232 (head `61e6643`), merged as `a777c87` on the Owner's message "Мёрдж #232", step 1 of the
optimization plan the Owner approved on 2026-11-20. It removed the line
`core-transport = { path = "../core-transport" }` from `crates/mobile-ffi/Cargo.toml` and that edge
from `Cargo.lock`; no package version changed. No status changes here: this section records what
the merge made stale in two earlier entries. Each `path:line` below was re-read at `6dd93b2`.

**Runtime evidence** at `6dd93b2`: `cargo tree --locked -p mobile-ffi -e normal,build --target
aarch64-linux-android` lists 131 packages (distinct name and version, `mobile-ffi` itself included; 390 at `ec6e00e`, before #232) and `--target
x86_64-linux-android` 132 (391 before); neither lists `core-transport`, `arti-client`, a `tor-*` crate,
`ring` 0.16 or `rsa`. `grep -rn "core_transport\|TorTransport" crates/mobile-ffi/` → no match, and no package in `Cargo.lock`
lists `core-transport` as a dependency.

| ID | Status at `6dd93b2` | Evidence (`main` @ `6dd93b2`) | Label |
|----|-------------------|-----------------------------|-------|
| **F-15** (Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir`) | Note only; status unchanged (**NOT-FIXED (design)** · `NEEDS-HOME`). The scope text "`core-transport` is a `mobile-ffi` dependency in `Cargo.toml` but no source in `crates/` calls it" is stale in its first half: `mobile-ffi` no longer depends on `core-transport`, so arti is not compiled into the Android library. Its second half still holds: nothing outside `crates/core-transport` calls it. #232 changes neither (a) nor (b): (a) has had no code since PR #157 deleted `SolanaClient.kt` (see "Update 2026-11-14: R-7 (b), R-10 and R-17 fixed"); (b) still holds, now at `crates/core-transport/src/lib.rs:40` (`_state_dir`) and `:43` (`TorClientConfig::default()`). *(Note 2026-11-24: (b) is fixed by PR #265; see "Update 2026-11-24: Tor connector in core-transport".)* *(Note 2026-11-27: since PR #275 `mobile-ffi` depends on `core-transport` again and calls it, for a relay at an onion address; see "Update 2026-11-27: Tor for onion relays".)* | `crates/mobile-ffi/Cargo.toml:11-23` (the dependency list, no `core-transport`); `mobile-ffi`'s `Cargo.lock` entry lists none; the `cargo tree` and `grep` above | `SOURCE_VERIFIED`, `RUNTIME_VERIFIED` |
| **D-008** (lead of 2026-11-06; FIXED by PR #137, see "D-008 and D-010: fixed or decided") | Note only. Its sub-bullet "`mobile-ffi` lists `core-transport` as a dependency (`crates/mobile-ffi/Cargo.toml:16`)" is stale; the rest of that bullet still holds: no source names it, and the Kotlin `startTorTransport` throws, now at `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt:266-272` (the lead cites `:263-269`). *(Note 2026-11-27: since PR #275 `mobile-ffi` names `core_transport` (`network/tor.rs`); see "Update 2026-11-27: Tor for onion relays".)* *(Note 2026-11-28: the Kotlin `startTorTransport` was removed by PR #276; see "Update 2026-11-28: Tor route in Settings and core fixes".)* | as above | `SOURCE_VERIFIED` |

Not a row: the `.cargo/audit.toml` ignores of RUSTSEC-2025-0009 (`ring` 0.16) and RUSTSEC-2023-0071
(`rsa` 0.9) concern crates that stay in `Cargo.lock` through `core-transport`; they are no longer in the
`mobile-ffi` build for either Android target (the `cargo tree` above). The ignores stay as they are
(`CLAUDE.md`, «Постоянные ограничения»). *(Note 2026-11-24: PR #262 removed the RUSTSEC-2025-0009 ignore: `ring` 0.16 has left `Cargo.lock`; see "Update 2026-11-24: arti 0.48 in core-transport".)* *(Note 2026-11-27: since PR #275 `rsa` is in the `mobile-ffi` build again, through `core-transport`; the RUSTSEC-2023-0071 entry gives the reasoning; see "Update 2026-11-27: Tor for onion relays".)*

---

## Update 2026-11-21: code locations after the split (`main` @ `43a5ae1`)

**Snapshot:** `main` @ `43a5ae185fdfb29d8894aefcd1e15317c0849f91` (the merge of PR #244). Step 7 of the
optimization plan the Owner approved on 2026-11-20 moved code out of `crates/mobile-ffi/src/lib.rs` and
`crates/mobile-ffi/src/network.rs` without changing it:

- PR #240 (merged as `bfad8c0`) moved `lib.rs`'s inline tests to `src/tests/mod.rs`;
- PR #241 (`ed0cad6`) moved its code into `error.rs`, `identity.rs`, `prekeys.rs`, `handshake.rs` and `responder.rs`;
- PR #242 (`5a32f0c`) moved `network.rs`'s internals into `network/far_skip.rs`, `inbox.rs`, `mailbox.rs`,
  `outbox.rs`, `refusals.rs` and `tests.rs`.

Each was a pure move: every moved line equals an old one apart from added visibility qualifiers (and a
four-space dedent of the two moved test modules, `src/tests/mod.rs` and `network/tests.rs`), the test
names are the same 307, and the generated Kotlin bindings are byte-identical (see each PR).

**No status changes here.** This section gives, for the live rows whose newest code evidence cites those
two files, where each cited item is now. Each `path:line` below was re-read at `43a5ae1`. The anchor in
brackets is the one the cited row gives, at that row's commit. `network/chat.rs` was not part of the
split. Older rows keep the snapshot they cite (the F-, H- and A-series of 2026-09-29, and anchors in
FIXED rows): their line numbers had moved before the split too, and their items are found by name.

| ID | Status at `43a5ae1` | Where the cited items are now (`main` @ `43a5ae1`; the row's anchor in brackets) | Label |
|----|---------------------|-------------------------------------------------------------------------------|-------|
| **R-21** (row of 2026-11-20, `main` @ `7b6677f`) | Unchanged (**PARTIAL — narrowed further**). | `FORGOTTEN_SEEN_PER_SESSION` `crates/mobile-ffi/src/network.rs:288` (`:460`); the decision (a message of a forgotten chain is named on its second arrival) `crates/mobile-ffi/src/network/inbox.rs:224` (`network.rs:1504`), `seen_again` `inbox.rs:365` (`:1669`), `forget_forgotten_notes` `inbox.rs:387` (`:1691`), `name_gone` `inbox.rs:502` (`:2170`) | `SOURCE_VERIFIED` |
| **R-14** (row of 2026-11-19, `main` @ `2a6074f`) | Unchanged (**PARTIAL**). | `far_wait_key` `crates/mobile-ffi/src/network/far_skip.rs:27` (`network.rs:295`), `pack_far_waits` `far_skip.rs:42` (`:310`), `unpack_far_waits` `far_skip.rs:56` (`:324`), `note_far_sighting` `far_skip.rs:93` (`:361`), `far_candidate` `far_skip.rs:163` (`:1883`), `forget_far_waits` `far_skip.rs:221` (`:1941`), `stored_far_waits` `far_skip.rs:242` (`:1962`), `store_far_waits` `far_skip.rs:271` (`:1991`), `far_progress` `far_skip.rs:306` (`:2026`), `far_pass` `far_skip.rs:327` (`:2047`), the unit tests `crates/mobile-ffi/src/network/tests.rs` (`network.rs:2281`; declared at `network.rs:959`); still in `network.rs`: `FAR_SKIP_WAIT` `crates/mobile-ffi/src/network.rs:272` (`:430`), `FAR_CHAINS_PER_SESSION` `network.rs:282` (`:440`), `this_millis` `network.rs:848` (`:2170`) | `SOURCE_VERIFIED` |
| **R-20** (row of 2026-11-19, `main` @ `2a6074f`) | Unchanged (**PARTIAL — narrowed with R-14**). | Its evidence is R-14's ("as R-14"): see the row above. | `SOURCE_VERIFIED` |
| **R-9** (row of 2026-11-18, `main` @ `c2acfb6`) | Unchanged (**OPEN — narrowed further**). | still in `network.rs`: `connect_owner` `crates/mobile-ffi/src/network.rs:639` (`:668`), `connect` `network.rs:624` (`:653`); `send_to` `crates/mobile-ffi/src/network/outbox.rs:100` (`network.rs:1037`) | `SOURCE_VERIFIED` |
| **R-6** (row of 2026-11-19, `main` @ `553c3ba`) | Unchanged (**PARTIAL — rotated; the key-compromise route bounded**). | the record and the rule: `PREKEY_RECORD_V3_LEN` `crates/mobile-ffi/src/prekeys.rs:125` (`lib.rs:429`), `SIGNED_PREKEY_PERIOD_SECS` `prekeys.rs:140` (`:444`), `renew_one_time_prekey` `prekeys.rs:242` (`:546`), `unpack_prekeys` `prekeys.rs:289` (`:593`), `plan_rotation` `prekeys.rs:391` (`:695`), `rotate_signed_prekey` `prekeys.rs:409` (`:713`); `check_answerable` `crates/mobile-ffi/src/responder.rs:17` (`:1339`), `accept_first_message` `responder.rs:93` (`:1415`), `replace_prekey_on_confirm` `responder.rs:199` (`:1521`); still in `lib.rs`: `maintain_prekeys` `crates/mobile-ffi/src/lib.rs:489` (`:1672`), `note_prekeys_published` `lib.rs:533` (`:1716`); the round, still in `network.rs`: `put_bundle` `crates/mobile-ffi/src/network.rs:711` (`network.rs:748`), called before the mailbox at `network.rs:769` (`:806`), the clock `this_second` `network.rs:860` (`:1971`) | `SOURCE_VERIFIED` |
| **R-13** (row of 2026-11-19, `main` @ `8bac3f3`) | Unchanged (**PARTIAL — a way out by a reset (option B)**). | the restart check `crates/mobile-ffi/src/network/inbox.rs:127` (`network.rs:1254`); `replace_prekey_on_confirm` `crates/mobile-ffi/src/responder.rs:199` (`lib.rs:1272`); still in `lib.rs`: `replace_prekey_once` `crates/mobile-ffi/src/lib.rs:448` (`:1379`) | `SOURCE_VERIFIED` |
| **H-7** (row of 2026-11-15, `main` @ `79be252`) | Unchanged (**OPEN — narrowed**). | Of the three `mobile-ffi` sites the row names (`lib.rs:266, 422, 432`), the identity secret's copy is now `crates/mobile-ffi/src/identity.rs:90` (`:266`). The one-time and signed prekey secrets (`:422`, `:432`) have been read by one closure, `secret_at` in `unpack_prekeys`, since PR #222 changed the prekey record (two sites in `lib.rs` at `553c3ba`, before the split); it is now `crates/mobile-ffi/src/prekeys.rs:323`. The by-value copy in `StaticSecret::from([u8; 32])` is the same at both. | `SOURCE_VERIFIED` |

---

## Update 2026-11-22: process-kill tests inside a round (`main` @ `4ad3337`)

**Snapshot:** `main` @ `4ad3337655fa14db7d652a4bc90d7b6767dd4905` (the merge of PR #251, head `a6548e8`; the same tree
as that head). Steps 0 to 1.3 of the reliability plan the Owner approved on 2026-11-22 ("Утверждаю этот
план"; continuity record D-080). PRs #248 (merged as `cb3e5b3`), #249 (`c3f1c1b`), #250 (`031da1c`) and
#251 (`4ad3337`) add tests that kill the process at a named point of a network round, and four crash
points; the body of `crash_point` is compiled into tests only (`crates/mobile-ffi/src/network.rs:874`),
and #251 changes test files only. PR #247 (`74aece2`) changes two doc comments. The merges were on the
Owner's messages "Мёрдж #247 и #248", "Мерж 249", and "Мерж" for #250 and for #251 (the agent had asked
for each by its number, and it was the only open PR at the time). Normal merge commits pinned with `expectedHeadSha`.
Each `path:line` below was re-read at `4ad3337`.

**No status changes here.** A process death is not one of the tracker's findings; this section records
which points now have a test, for the rows that name such a point as untested, and what is still not
tested.

**What each test kills, and what it asserts after the restart.** The child is the test binary run as a
second OS process on the device's database; it dies by `abort()` (`run_child`,
`crates/mobile-ffi/src/tests/network_crash.rs:75`).

| Point (crash point) | Where | Test | Asserted after the restart |
|---|---|---|---|
| a receipt applied, the receipt message not yet acknowledged (`receipt_applied`) | `settle`, `crates/mobile-ffi/src/network/inbox.rs:446` | `network_crash.rs:199` | the delivery is stored; the receipt message is still in the inbox; the next round settles it and counts no second delivery |
| the text a GONE message names abandoned, the GONE message not yet acknowledged (`gone_applied`) | `settle`, `inbox.rs:467` | `network_crash.rs:239` | the text is abandoned; the GONE message is still in the inbox; the next round settles it |
| the receipt for an OPEN message committed, the OPEN message not yet acknowledged (`open_receipted`) | `settle`, `inbox.rs:435` | `network_crash.rs:306` | the session exists; one receipt for the OPEN message is in the outbox; the OPEN message is still in the inbox; after the next rounds the initiator's OPEN message is confirmed |
| the relay accepted a receipt, the receipt not yet removed from the outbox (`receipt_published`) | `publish_pending`, `crates/mobile-ffi/src/network/outbox.rs:191` | `network_crash.rs:364` | the receipt is still in the outbox; the sender's next round counts the delivery (the relay had accepted the receipt); the receipt is then sent again and the delivery is not counted again |
| a far skip committed a message (`after_accept` in `far_pass`), and its receipt committed too (`after_settle` there; the message pass uses the same two names, `inbox.rs:155`, `:157`) | `far_pass`, `crates/mobile-ffi/src/network/far_skip.rs:346`, `:354` | `crates/mobile-ffi/src/tests/far_skip.rs:113` | the text is shown once; the relay holds no message for the recipient; the stored wait is gone; no receipt (first point) or one committed and unsent (second point); after the next rounds the sender has the text delivered |

**Runtime evidence.** Locally, on `4ad3337`: `cargo test --workspace --locked` → exit 0;
`core-crypto`: `test result: ok. 136 passed; 0 failed`; `core-protocol`: `test result: ok. 149 passed; 0 failed`;
`mobile-ffi`: `test result: ok. 311 passed; 0 failed; 1 ignored`; `relay`: `test result: ok. 62 passed; 0 failed`; every other test binary `0 failed`;
`cargo clippy --workspace --locked -- -D warnings` → exit 0.
CI: 9 check runs, all success, on each merged head (#247 `d34eb7a`, #248 `48fd19f`, #249 `316da2b`,
#250 `43f3509`, #251 `a6548e8`), including the emulator jobs; the push runs on `main` were not read.
Mutations (scratch edits, reverted), each failing the named test: the two steps swapped in the receipt
and GONE arms (#248, both tests), in the OPEN arm (#249), the acknowledge before the send (#250), and
for #251 three: no `settle` in `far_pass`, no `settle_inbox` at the start of a round, and a crash
point that never fires. Fresh-context reviews: one each for #248 to #251, nothing blocking; what they
found was applied before the commit (in #251: at `after_accept` the first version of the test passed
even if the crash point never fired), except one LOW point in #249 that its description states.
The reviewers did not run the tests. A review is analysis, not proof.

| ID | Status at `4ad3337` | Evidence (`main` @ `4ad3337`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-14** (more than `MAX_SKIP` lost messages stop a direction) | Note only; status unchanged (**PARTIAL — narrowed**). A message read with a far skip is deleted from the relay in the message pass, before the far pass reads it, so once the far skip committed it, on the recipient's side only its store holds it. A death of the process in the far pass, after the far skip committed the message and after its receipt was committed, now has a test: a second OS process makes the commit and dies, and the restarted device shows the text once and confirms it. **Still not tested** (the 2026-11-19 row's list is unchanged): a process death after the message pass deleted the far message from the relay and before the far skip committed it (the message is then held only in that process's memory; `far_pass`'s comment says it is read only when it comes again); a process death between the far skip's commit and the delete of the stored wait (`far_progress` runs before the first crash point, so the test dies after that delete); the stored wait read back by another OS process (the child sets the wait to zero and writes and deletes the record itself); store faults. | `far_pass` (`crates/mobile-ffi/src/network/far_skip.rs:327`), `far_progress` called at `:345`, the crash points `:346`, `:354`; the scenario `far_sync` (`crates/mobile-ffi/src/tests/network_crash.rs:40`); test `crates/mobile-ffi/src/tests/far_skip.rs:113` | `SV`; `RUNTIME_VERIFIED` (the test, three mutations, CI) |
| **R-20** (cancelling more than `MAX_SKIP` encrypted texts in a row leaves a gap that stops the chain) | Note only; status unchanged (**PARTIAL — narrowed with R-14**). | as R-14 | `SV` |
| **R-21** (a late message whose skipped key was evicted is lost, and its sender keeps resending it) | Note only; status unchanged (**PARTIAL — narrowed further**). The sender's side of a GONE message now has a process-kill test: a death after the named text was abandoned and before the GONE message was acknowledged leaves the text abandoned, and the next round settles the GONE message. **Not tested:** a death of the device that sends a GONE message between the relay accepting it and its leaving the outbox (the crash point `receipt_published` fires for a GONE message too; only a receipt is tested there). | `settle` (`crates/mobile-ffi/src/network/inbox.rs:421`), the GONE arm's crash point `:467`; `crates/mobile-ffi/src/network/outbox.rs:191`; test `crates/mobile-ffi/src/tests/network_crash.rs:239` | `SV`; `RUNTIME_VERIFIED` (the test, one mutation, CI) |

Not rows:

- Every test here kills a process. None cuts power or makes a storage write fail, so none shows what a
  commit that the operating system had not yet written to the device survives (stages 2 and 3 of the
  plan; `NOT_VERIFIED`).
- PR #247 corrected the doc comments of `Recovery::artifact_committed`
  (`crates/core-protocol/src/messaging/types.rs:191`) and `RecoveryReport::artifact_committed`
  (`crates/mobile-ffi/src/messaging_api.rs:154`): the field says that the store, as read now, holds a
  record under one of the keys the unresolved transition writes, not that this transition wrote it
  (another instance on the same database may have). Comments only: no code changed.

---

## Update 2026-11-24: arti 0.48 in core-transport (`main` @ `c73bbbe`)

**Snapshot:** `main` @ `c73bbbe419c88169eb113fea7c83032e0553b2ae`, the merge of PR #262 (a normal merge
commit, parents `b1f6a37` and the head `c5960b3`; the same tree as that head). Step 2.1 of the Tor plan the
Owner approved on 2026-11-24 (continuity record D-102). PR #262 raised `arti-client` and `tor-rtcompat` in
`crates/core-transport` from 0.21 to 0.48, changed one line of `crates/core-transport/src/lib.rs` and added a
test there, re-vendored `vendor/tor-dirmgr` at 0.48.0, and changed `Cargo.lock`, `.cargo/audit.toml`, the
RUSTSEC-2026-0387 guard, `arcium-ci.yml`, `CLAUDE.md` and `vendor/README.md`, and comments in the root
`Cargo.toml` and in `crates/core-crypto/tests/feature_graph.rs`. The merge
was on the Owner's message "ША-2 принимаю. Мерши 262.". This section covers #262 only. Each `path:line`
below was re-read at `c73bbbe`.

**No status changes here.** Tor is still not wired into the app: `crates/mobile-ffi/Cargo.toml` does not
name `core-transport`, and the Kotlin `startTorTransport` still throws
(`android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt:266-272`). This section records what
the upgrade made stale in earlier entries and what it changed in the graph the app is built from. *(Note 2026-11-27: since PR #275 the app's core uses Tor for a relay at an onion address; see "Update 2026-11-27: Tor for onion relays".)* *(Note 2026-11-28: the Kotlin `startTorTransport` was removed by PR #276; see "Update 2026-11-28: Tor route in Settings and core fixes".)*

**What the Android library is built from.** `cargo tree --locked -p mobile-ffi -e normal,build --target
aarch64-linux-android` lists 131 packages (distinct name and version) at `c73bbbe` and at `b1f6a37`, before
#262; `--target x86_64-linux-android` lists 132 at both. Between the two commits exactly two versions
differ, on both targets: `sha2` 0.11.0 → 0.11.1 and `serde_json` 1.0.151 → 1.0.154 (PR #262's description
names `tor-llcrypto` 0.48 and `tor-persist` 0.48 as what forced them). Neither list contains
`core-transport`, `arti-client`, a `tor-*` crate or `rsa`, and the only `ring` in them is 0.17.14. With the
enabled features listed too (the same command with `-f '{p} [{f}]'`), the same two lines differ and nothing
else: `serde_json` keeps `default`, `std` and `unbounded_depth`, and `sha2` keeps `alloc`, `default`, `oid`
and `zeroize`.

**`sha2` 0.11.1.** Its changelog (`sha2-0.11.1/CHANGELOG.md:8-20`) lists the removal of a workaround for
unaligned loads in the `riscv-zknh` backend, `riscv-zknh` no longer requiring `zbkb` or `zbb`, MSRV 1.88,
and one fix: "Loading of round constants in AArch64 backends to satisfy the Stacked Borrows model". The
sources of 0.11.0 and 0.11.1 also differ in `block_api.rs` (the loops that write the output and serialize
and deserialize the state), `consts.rs`, `sha256.rs`, `sha512.rs` and the AArch64, x86, wasm32 and riscv backends (`diff
-r` of the two crate sources). The drop cleanup A-3.5 cites at `sha2-0.11.0/src/block_api.rs:89-101` reads
the same in 0.11.1, at `block_api.rs:92-104`. `sha2` 0.11.1 has the features `alloc`, `default`, `oid` and
`zeroize` (`cargo tree -e features -i sha2@0.11.1`), and core-crypto's `tests/feature_graph.rs` passes.
Only the workspace's own crates turn on `zeroize` of `sha2` 0.11.1 (`core-crypto`, `core-protocol`,
`core-storage`, `mobile-ffi`, `relay`) and of `hmac` 0.13.0 (`core-crypto`, `relay`); `digest` 0.11.3's
`zeroize` is turned on only through those two; no Tor crate turns on any of the three (`cargo tree
--workspace -e features -i <crate> --depth 2`). So the Tor crates do not hide a missing feature from
A-3.5's type pins in a workspace run. The hashes themselves: core-crypto's golden vectors, the contact hash
among them, pass on x86_64 with 0.11.1 (below), and under `qemu-aarch64-static -cpu max` for
`aarch64-unknown-linux-gnu` they passed with 0.11.0 and with 0.11.1 (`136 passed; 0 failed` each; `sha2`'s
own tests `14 passed; 0 failed` each; recorded in PR #262's description, which also records `is_aarch64_feature_detected!("sha2")` = true under
that emulator; that `sha2` then chose its AArch64 hardware backend, where the 0.11.1 fix is, is `INFERRED`,
not observed). QEMU emulates the SHA instructions; no phone was used (`NOT_VERIFIED` on a device). H-9 cites `sha2` backend lines in 0.11.0
(`x86_sha.rs:46`, `aarch64_sha2.rs:13`); in 0.11.1 those backends' `compress` is at `x86_sha.rs:75` and
`aarch64_sha2.rs:10`, and `soft/unroll.rs` is unchanged. The residuals H-9 lists were not re-read in 0.11.1
(`NOT_VERIFIED`), and A-3.5's temporary controls were not re-run.

**The rest of the graph** (`Cargo.lock`). `ring` 0.16.20 has left it; only `ring` 0.17.14 remains, used by
`rustls` and `rustls-webpki`. `.cargo/audit.toml` no longer ignores RUSTSEC-2025-0009 and says why
(`:7-8`), and `CLAUDE.md` no longer names it. `hkdf` 0.12.4 has left it too. `hmac` 0.12.1 is now used only
by `rfc6979`; `sha2` 0.10.9 by `ed25519-dalek` 2.2.0, `p256`, `p384`, `p521`, `rsa`,
`ssh-encoding-fork-arti` and `ssh-key-fork-arti`; `tor-proto` uses `hmac` 0.13.0 and `hkdf` 0.13.0, and
`tor-llcrypto` uses `sha2` 0.11.1 and `ed25519-dalek` 3.0.0. `core-crypto` and `mobile-ffi` still use
`ed25519-dalek` 2.2.0 over `sha2` 0.10.9, so H-9's sentence on the Ed25519 signing key still holds (the key is now generated at
`crates/mobile-ffi/src/identity.rs:46`; H-9's anchor `lib.rs:207` predates the split of PRs #240–#242). The
other two ignores stay: `rsa` 0.9.10 (RUSTSEC-2023-0071) is used by `tor-llcrypto`, `tor-key-forge` and
`ssh-key-fork-arti`, and `crypto-bigint` 0.5.5 (RUSTSEC-2026-0387) by `elliptic-curve`; their entries
give this provenance (`.cargo/audit.toml:12-46`), and `CLAUDE.md:174-177` now also asks for the `rsa`
ignore to be reviewed before Tor enters the app. The RUSTSEC-2026-0387 guard now looks for
`ssh-key-fork-arti`, arti 0.48's fork of `ssh-key` (`.github/scripts/check_rustsec_2026_0387.py:50`).

**Runtime evidence.** Locally, on `c73bbbe`: `cargo test --workspace --locked` → exit 0; `core-crypto`: `test result: ok. 136 passed; 0 failed`;
its `tests/feature_graph.rs`: `test result: ok. 2 passed; 0 failed`; `core-protocol`: `test result: ok. 169 passed; 0 failed`;
`core-storage`: `test result: ok. 64 passed; 0 failed; 2 ignored`; `core-transport`: `test result: ok. 9 passed; 0 failed; 1 ignored`;
`mobile-ffi`: `test result: ok. 313 passed; 0 failed; 1 ignored`; `relay`: `test result: ok. 62 passed; 0 failed`; every other test binary `0 failed`;
`cargo clippy --workspace --locked -- -D warnings` → exit 0. CI: all 9 check runs success on the merged
head `c5960b3`; on `main` @ `c73bbbe` the push runs of Arcium CI, Android Native Bridge, Android
Instrumentation and Android two-device messaging all concluded success (Arcium CI run 45385121946).

| ID | Status at `c73bbbe` | Evidence (`main` @ `c73bbbe`) | Label |
|----|---------------------|-------------------------------|-------|
| **F-15** (Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir`) | Note only; status unchanged (**NOT-FIXED (design)** · `NEEDS-HOME`). arti is 0.48 now. (b) still holds: `new_within` ignores its directory (`_state_dir`) and builds `TorClientConfig::default()`. Nothing outside `crates/core-transport` calls it: `git grep -n 'core_transport\|TorTransport\|core-transport' c73bbbe -- crates android ':!crates/core-transport'` finds only comments, `android/README.md`, and the Kotlin stub's name and error text. *(Note 2026-11-24: (b) is fixed by PR #265; see "Update 2026-11-24: Tor connector in core-transport".)* *(Note 2026-11-27: the Tor transport now has a caller in the app's core, for a relay at an onion address only (PR #275); see "Update 2026-11-27: Tor for onion relays".)* *(Note 2026-11-28: the Kotlin stub was removed by PR #276; see "Update 2026-11-28: Tor route in Settings and core fixes".)* | `crates/core-transport/src/lib.rs:40`, `:43`; `crates/core-transport/Cargo.toml:13`, `:20` | `SOURCE_VERIFIED` |
| **D-008** (lead of 2026-11-06; FIXED by PR #137) | Note only. The bootstrap bound is unchanged: `BOOTSTRAP_TIMEOUT` = 120 s, `new` calls `new_within` with it, and `bootstrap_within` wraps the bootstrap in `tokio::time::timeout`. The ignored test `new_fails_gracefully_without_tor` moved (`#[ignore]` at `:192`, the function at `:193`); it was not run here (`NOT_VERIFIED`), so nothing here shows arti 0.48 bootstrapping or failing within the bound against a real network. *(Note 2026-11-24: these lines moved in PR #265; see "Update 2026-11-24: Tor connector in core-transport".)* | `crates/core-transport/src/lib.rs:15`, `:35-37`, `:59-71`, `:192-193` | `SOURCE_VERIFIED` |
| **A-3.5** (upstream-supported partial hardening of `hmac`, `hkdf`, `sha2`) | Note only; status unchanged (**FIXED — merged** in PR #110). `sha2` is 0.11.1 with `zeroize`; the `Sha256VarCore` drop cleanup it cites reads the same, at new lines; `hkdf 0.12.4` is gone, so its last sentence now holds for `hmac 0.12.1` and `sha2 0.10.9` only. | `sha2-0.11.1/src/block_api.rs:92-104`; `Cargo.lock`; core-crypto `tests/feature_graph.rs` | `SOURCE_VERIFIED`, `RUNTIME_VERIFIED` (`feature_graph`, golden vectors) |
| **H-9** (secret-derived state inside `hmac`, `hkdf`, `sha2`) | Note only; status unchanged (**PARTIALLY_FIXED**). `sha2` is 0.11.1; the backend lines it cites moved (above), and the residuals were not re-read in 0.11.1. Its list of old lines is stale: `hkdf 0.12.4` is gone; `hmac 0.12.1` serves `rfc6979` only; `sha2 0.10.9` serves `ed25519-dalek` 2.2.0, `p256`/`p384`/`p521`, `rsa`, `ssh-encoding-fork-arti` and `ssh-key-fork-arti`, not `tor-llcrypto`. The Ed25519 sentence still holds (the key is generated at `crates/mobile-ffi/src/identity.rs:46`). | `Cargo.lock`; `sha2-0.11.1/src/sha256/x86_sha.rs:75`, `aarch64_sha2.rs:10` | `SOURCE_VERIFIED`; residuals `NOT_VERIFIED` |

Not rows:

- Other places that name `sha2 0.11.0` or `ring` 0.16 (F-8, A-3.7 and the history list under "Prioritized
  remaining work") record the state at the commits they cite and keep that snapshot.
- For the step that wires Tor into the app (not findings; recorded so that step can check them):
  arti 0.48 can end the process with `std::process::exit(1)` (`arti-client-0.48.0/src/client.rs:1321`),
  in the callback it passes to `enforce_protocol_recommendations` (`:1301`), which prints "Shutting down
  because of unsupported software version" (`:1312`). core-transport turns on `rustls`'s `ring` feature
  (`crates/core-transport/Cargo.toml:29`) and installs no provider itself; the test
  `a_tor_client_can_be_created_from_this_crate_alone` (`crates/core-transport/src/lib.rs:169`) asserts that
  a process-level provider exists once a client has been created (`:179-182`). Wiring Tor in puts `rsa` in
  the Android library (`.cargo/audit.toml`, the RUSTSEC-2023-0071 entry). *(Note 2026-11-24: since PR #265 that test is at `crates/core-transport/src/lib.rs:205` and its assertion at `:215-218`; see "Update 2026-11-24: Tor connector in core-transport".)* *(Note 2026-11-27: answered by PR #275 and recorded in "Update 2026-11-27: Tor for onion relays".)*

---

## Update 2026-11-24: Tor connector in core-transport (`main` @ `e690168`)

**Snapshot:** `main` @ `e690168457c54907a0757739bea1a71f4a4a2849`, the merge of PR #265 (a normal merge
commit, parents `3840efc` and the head `9724da9`; the same tree as that head), on the Owner's message "265,
а потом трекер.". Steps 3.1 and 3.2 of the Tor plan the Owner approved on 2026-11-24 (continuity record
D-102). PR #264 (head `ae661ae`, merged as `3840efc`) gave the relay client a connector seam: it opens its
stream through a `Connector` (`crates/relay/src/client.rs:195`) and runs over any `RelayStream` (`:169`);
`Connection::connect` and `connect_v2` use `TcpConnector` (`:204`), so the app still connects over direct
TCP (TLS for V2), not Tor (`crates/mobile-ffi/src/network.rs:626-627`). PR #265 added a Tor connector to `crates/core-transport`
(`TorConnector`, `TorStream`, `crates/core-transport/src/connector.rs`) and made the Tor client use the
directory it is given. This section covers #264 and #265 only. Each `path:line` below was re-read at
`e690168`.

**One status change:** F-15(b) is fixed in code. The Tor transport still has no caller in the app: wiring it
in is step 4.1. *(Note 2026-11-27: step 4.1's Rust part is merged, PR #275; see "Update 2026-11-27: Tor for onion relays".)*

**F-15(b), the fix.** `builder` (`crates/core-transport/src/lib.rs:89`) builds arti's configuration with
`TorClientConfigBuilder::from_directories(state_dir.join("state"), state_dir.join("cache"))` (`:91`).
`TorTransport::create` (`:54`) builds every client with it, whether it bootstraps (`Start::Bootstrap`) or
not (`Start::Unbootstrapped`, compiled into tests only: the variant at `:81-82`, its arm at `:58-62`); `new` and `new_within` go through `create`
(`:40-48`), and so does `TorConnector::bootstrap` (`connector.rs:43`, `:47-49`). The test
`the_client_keeps_its_state_and_cache_under_the_given_directory` (`lib.rs:227`) creates a client through
`create` without bootstrapping and finds its state lock, its key store and its cache lock under the given
directory (`RUNTIME_VERIFIED`); a mutation that moves both directories elsewhere fails it (PR #265's
description). **Not verified:** the bootstrap itself (`Start::Bootstrap`) runs only in the ignored test
`new_fails_gracefully_without_tor` (`:243-248`), which needs the network and was not run, so what arti
writes while and after it bootstraps was not observed (`NOT_VERIFIED`); a revert of that branch alone to
arti's default directories passes the tests and only raises rustc's unused-variable warning, which CI's
`cargo clippy -- -D warnings` turns into an error (the reviewer's mutation, PR #265's description); arti's permission checks on these directories on Android
were not run (`NOT_VERIFIED`).

**The connector, for R-4.** `TorConnector::connect` (`connector.rs:61`) passes `host:port` to arti as
written, so no name is looked up on the device (`SOURCE_VERIFIED`: the `&str` goes to `client.connect`,
`:64`, and arti-client 0.48 looks no name up locally; no test observes it), and returns within its timeout
(`open`, `:70-76`); a zero timeout is refused. Local and private addresses are refused by arti before anything is sent (test
`a_local_address_is_refused`, `:372`). `TorStream` (`:101`) bounds a read and a write by the timeouts the
relay client sets before each (`:122`, `:127`), and a flush by the write timeout set last, counted from
when it was set (`:130`, `:150`). The relay client sets those timeouts before every read and write on any
connector's stream (`crates/relay/src/client.rs:98`, `:106`; test
`a_connection_bounds_each_read_and_write_on_a_connectors_stream`, `:743`). Tests, all offline and over stand-in streams (an in-memory pipe, a writer whose flush never ends) or a
connect that never finishes, not arti's stream:
`a_read_fails_at_the_read_timeout` (`connector.rs:243`), `a_write_fails_at_the_write_timeout` (`:256`),
`a_flush_fails_when_the_write_timeout_set_last_runs_out` (`:287`), `a_connect_returns_within_its_timeout`
(`:320`), `a_stream_outlives_its_connector` (`:388`). The unbounded name lookup R-4 lists as remaining is
unchanged and is now in `TcpConnector::connect` (`crates/relay/src/client.rs:206-209`), which the app still
uses. *(Note 2026-11-25: since PR #268 the relay client also sets the write timeout before every flush, to what is left of the request deadline; see "Update 2026-11-25: flush bounded by the request deadline".)*

**Runtime evidence.** Locally, on `e690168`: `cargo test --workspace --locked` → exit 0; `core-crypto`: `test result: ok. 136 passed; 0 failed`;
`core-protocol`: `test result: ok. 169 passed; 0 failed`; `core-storage`: `test result: ok. 64 passed; 0 failed; 2 ignored`;
`core-transport`: `test result: ok. 23 passed; 0 failed; 1 ignored`; `mobile-ffi`: `test result: ok. 313 passed; 0 failed; 1 ignored`;
`relay`: `test result: ok. 65 passed; 0 failed`; every other test binary `0 failed`;
`cargo clippy --workspace --locked --all-targets -- -D warnings` → exit 0. CI: all 9 check runs success
on the merged heads of #264 (`ae661ae`) and #265 (`9724da9`); on `main` @ `3840efc` the push runs of all
four workflows concluded success. On `e690168` Arcium CI, Android Native Bridge and Android two-device
messaging concluded success; Android Instrumentation failed on its first attempt before any test ran (the
runner could not install the emulator package: "Error reading Zip content from a SeekableByteChannel"; run
45462509921) and succeeded on its one re-run. Nothing here was run over the
Tor network or on a phone.

| ID | Status at `e690168` | Evidence (`main` @ `e690168`) | Label |
|----|---------------------|-------------------------------|-------|
| **F-15** (Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir`) | (b) **FIXED** in PR #265 (merge `e690168`): the Tor client keeps its state and cache under the directory it is given. (a) unchanged (**NOT-FIXED (design)**; no code since PR #157) and `NEEDS-HOME` unchanged. The row's status is given per part. The transport still has no caller in the app (step 4.1). *(Note 2026-11-27: the caller came with PR #275; see "Update 2026-11-27: Tor for onion relays".)* | `crates/core-transport/src/lib.rs:54`, `:89-91`; `connector.rs:43-49`; test `lib.rs:227` | `SOURCE_VERIFIED`, `RUNTIME_VERIFIED` (test, mutation); bootstrap path and Android `NOT_VERIFIED` |
| **D-008** (lead of 2026-11-06; FIXED by PR #137) | Note only. The bound is unchanged: `BOOTSTRAP_TIMEOUT` = 120 s (`lib.rs:20`); `new` → `new_within` → `create`, which wraps the bootstrap in `bootstrap_within` (`:40-48`, `:54`, `:100`); `TorConnector::bootstrap` uses the same bound. `state_dir` is used now (F-15 above). The ignored test `new_fails_gracefully_without_tor` is at `:243-244` and was not run (`NOT_VERIFIED`). | `crates/core-transport/src/lib.rs:20`, `:40-54`, `:100`, `:243-244`; `connector.rs:43` | `SOURCE_VERIFIED` |
| **R-4** (no time bound on a relay operation or a sync round; FIXED by PR #145, with remainders) | Note only; status unchanged. The remainder "the DNS lookup in `Connection::connect` … is not bounded" now lies in `TcpConnector::connect`, the relay client's default connector (PR #264). `TorConnector::connect` looks no name up and is bounded by its timeout, but the app does not use it yet. After `connect`, the request deadline (`REQUEST_DEADLINE`, `client.rs:56`) applies to any connector's stream that keeps `RelayStream`'s contract on timeouts and flush (`:154-168`). *(Note 2026-11-25: that contract changed in PR #268, which bounds a flush in code; see "Update 2026-11-25: flush bounded by the request deadline".)* *(Note 2026-11-27: since PR #275 the app uses `TorConnector` for a relay at an onion address; see "Update 2026-11-27: Tor for onion relays".)* | `crates/relay/src/client.rs:56`, `:98`, `:106`, `:206-209`; `crates/core-transport/src/connector.rs:61-76`; tests named above | `SOURCE_VERIFIED`, `RUNTIME_VERIFIED` (tests over stand-in streams; arti's stream not exercised) |

Not rows:

- Earlier rows and sections that say F-15(b) still holds keep their snapshots: the F-15 row, D-008's lead
  and row, and the 2026-11-20 and "arti 0.48 in core-transport" sections; each has a dated note pointing
  here. The task list of 2026-11-06 ("`state_dir` handling (F-15(b)) is a separate item") is history.
- Older anchors in `crates/relay/src/client.rs` that predate #264 (for example `:35`, `:45-46`, `:87`, `:99`)
  keep the snapshots they cite.
- For step 4.1 (not findings): the app joins `TorConnector`/`TorStream` to the relay client with a newtype
  wrapper (core-transport does not depend on `relay`); it should never fall back to `TcpConnector` for an onion host,
  nor after a Tor error (the Owner's choice T3 as recorded, В; to be confirmed before 4.1); a connect and I/O timeout suited to Tor is still to be chosen (the
  Android default is 10 s); authenticated and anonymous relay connections would share Tor's default stream
  isolation (PR #265's description). *(Note 2026-11-27: answered by PR #275 and recorded in "Update 2026-11-27: Tor for onion relays".)*

## Update 2026-11-25: flush bounded by the request deadline (`main` @ `fb34eba`)

**Snapshot:** `main` @ `fb34ebaae0931a9b25b1194b4d1fbb2a9d13b326`, the merge of PR #268 (a normal merge commit,
parents `4f290cb` and the head `3908696`; the same tree as that head), on the Owner's messages "Мерш." and
"268.". The point came from the first pilot of the Reliability System's review flow: its finding R267-1 on a
replay of #264 (PR #267, closed unmerged). This section covers #268 only. Each `path:line` below was re-read at
`fb34eba`.

**No status change.** A note on R-4.

**What changed.** `Socket::flush` (`crates/relay/src/client.rs:110-114`) now sets the write timeout to what is
left of the request deadline before it flushes, as `Socket::write` does before every write (`:104-108`).
`remaining` (`:86-92`) gives the smaller of what is left and the connection's timeout, and `TimedOut` once
nothing is left. Before #268 the connection set no timeout before a flush, and the bound on a flush rested on
`RelayStream`'s doc contract: a stream had to finish a flush within the write timeout set last, counted from when
it was set. The contract now says that before every write and every flush the connection sets the write timeout
to what is left of the deadline (`:156-162`). The `idle` field and `REQUEST_DEADLINE` docs say a flush is bounded
too (`:79`, `:53-55`). The plain path reaches `Socket::flush` through `Transport::flush` (`:148-153`) from
`write_frame` (`crates/relay/src/protocol.rs:198`). Under TLS, rustls flushes the same socket (`Transport::Tls`,
`client.rs:119`): in rustls 0.23.46 (the crate whose sha256 `48e13bd8…` is the one `Cargo.lock` pins),
`StreamOwned::flush` calls `Stream::flush` (`src/stream.rs:279-281`), which calls `self.sock.flush()` (`:170`).

**Tests.**
- `a_connection_bounds_each_read_and_write_on_a_connectors_stream` (`:741`) now also requires a
  `set_write_timeout` right before every flush.
- `a_flush_waits_at_most_for_what_is_left_of_the_request_deadline` (`:775`): with a 5 s connection timeout and
  a 300 ms request deadline, the timeout set before every flush is at most 300 ms.
- Mutations (PR #268's description): no timeout before a flush fails the first test; bounding the flush by the
  connection's timeout instead of the remaining deadline fails the second.
- Both tests run over a stand-in stream on the plain path.

**R-4.** Status unchanged. After `connect`, the request deadline now bounds a flush on any connector's stream
whose flush honours the write timeout set just before it; it no longer relies on the stream counting from the
last write's timeout. `TorStream` counts a flush from its last `set_write_timeout`
(`crates/core-transport/src/connector.rs:127-131`, `:150-154`), which would now be the one set just before the
flush, so its documented behaviour still fits (by reading: `TorStream` is not yet joined to the relay client,
that is step 4.1; `INFERRED`). The unbounded name lookup R-4 lists as remaining is unchanged in
`TcpConnector::connect` (`crates/relay/src/client.rs:206-209`). *(Note 2026-11-27: since PR #275 `TorStream` is joined to the relay client, for a relay at an onion address; see "Update 2026-11-27: Tor for onion relays".)*

**Runtime evidence.**
- Locally, on the head `3908696` (the same tree as `fb34eba`): `cargo test --workspace --locked` → exit 0, 14
  result lines all `ok`, 779 passed, 0 failed; `relay`: `test result: ok. 66 passed; 0 failed; 0 ignored; 0
  measured; 0 filtered out`; `cargo clippy --workspace --locked -- -D warnings` → exit 0.
- CI: all 9 check runs success on the head `3908696`. On `main` @ `fb34eba` the push runs of all four workflows
  (Arcium CI, Android Native Bridge, Android Instrumentation, Android two-device messaging) concluded success.
- Reviews of #268:
  - a fresh-context agent (`engineering-code-review` and `arcium-security-review`): SHOULD-FIX, both points
    fixed before the merge, no security regression;
  - the Reliability System review: report APPROVE; it could not build in its sandbox and pointed to CI.
- Not run: anything over Tor or on a phone; a stalled flush through the relay client on either path (the tests
  check the timeout set before a flush, not that a stalled flush ends).

| ID | Status at `fb34eba` | Evidence (`main` @ `fb34eba`) | Label |
|----|---------------------|-------------------------------|-------|
| **R-4** (no time bound on a relay operation or a sync round; FIXED by PR #145, with remainders) | Note only; status unchanged. The request deadline bounds a flush in code, not by the `RelayStream` contract alone (PR #268). The name lookup in `TcpConnector::connect` is still unbounded. | `crates/relay/src/client.rs:86-92`, `:110-114`, `:156-162`, `:206-209`; tests `:741`, `:775` | `SOURCE_VERIFIED`, `RUNTIME_VERIFIED` (the timeout set before each flush, over a stand-in stream; no stalled flush) |

Not rows:

- The 2026-11-24 "Tor connector in core-transport" section (its paragraph "The connector, for R-4") and its R-4
  row describe the relay client's flush contract before #268; each has a dated note pointing here.
- Doc comments that bound every read and write and do not mention a flush are incomplete but not false:
  `crates/relay/src/client.rs:199-200`, `:218-219`, `:243-244`, `:264-265`, `crates/mobile-ffi/src/network.rs:407`,
  `docs/NET-MESSAGING.md:596`, `crates/core-transport/src/connector.rs:3-5`, `:80-82`.

---

## Update 2026-11-27: Tor for onion relays (`main` @ `2578962`)

**Snapshot:** `main` @ `2578962fdc1a9a63aaa9dbcf3443a62ed915e6a5`, the merge of PR #275 (a normal merge
commit, parents `ff31f93` and the head `79aba81`; the same tree as that head), on the Owner's message
"Мерж 275". It also covers PR #274 (head `a1feeef`, merged as `ff31f93`, parents `cec9242` and `a1feeef`), on
"Мерж 274". Step 4.1 of the Tor plan, the Rust part; the Owner's decisions for it are recorded on the
`continuity` branch (D-189, D-192 to D-195, D-199; D-190 was replaced by D-199, and D-191 belongs to the
release-build stage). This section covers #274 and #275 only. Each `path:line` below was
re-read at `2578962`.

**No status change.** Notes on F-15, D-008 and R-4.

**What changed.**
- **A caller for the Tor transport.** A relay whose host is an onion name (its last label `onion`, any case,
  final dots dropped: `is_onion`, `crates/mobile-ffi/src/network/tor.rs:45`; for a development `host:port`,
  `v1_host`, `:54`) is reached only through the process's one Tor client: `NetworkMessenger::connect`
  (`crates/mobile-ffi/src/network.rs:679`) sends it to `self.onion.connector()?` for V1 (`:682`) and V2
  (`:684`), and an error there ends the connection; nothing is tried directly. The production path is
  `ProcessTor` (`tor.rs:201`, its `OnionPath` impl at `:205`), which starts `TorConnector::bootstrap`
  (`:213`; it builds the client through `TorTransport::create`) once per process
  (`PROCESS_TOR`, `:197`) in `tor/` next to the store (`crates/mobile-ffi/src/lib.rs:95`). A relay at any
  other host is reached directly, as before (D-189). *(Note 2026-11-28: since PR #277 a development address that is not a well-formed `host:port` is reached by no path; see "Update 2026-11-28: Tor route in Settings and core fixes".)*
- **Bounds.** For an onion relay: 60 s to open the stream, or the connection's timeout if that is longer
  (`ONION_CONNECT_TIMEOUT`, `tor.rs:31`, used at `:257`), and 60 s per request (`ONION_REQUEST_DEADLINE`,
  `:35`; chosen in `network.rs:699`, set at `:689`); after a failed start, connections fail at once for 60 s
  (`RETRY_AFTER`, `tor.rs:40`), except after a start that panics, which skips that pause at this snapshot
  (`tor.rs:111-121`, `:186-188`; Arcium 2's R275-1, below). *(Note 2026-11-28: since PR #277 a start that panics pauses too; see "Update 2026-11-28: Tor route in Settings and core fixes".)* The first start waits up to `BOOTSTRAP_TIMEOUT`
  (120 s, `crates/core-transport/src/lib.rs:20`). A sync round's budget now counts from when its connection
  is open (`network.rs:838`).
- **The process exit (#274).** arti 0.48 ends the process once from a running client when the Tor network
  requires a protocol it lacks. If its directory cache is writable it has saved the requirement there
  before that, so while the cache is kept every later bootstrap fails with kind `SoftwareDeprecated`, which
  is now `TransportError::NeedsUpdate` (`crates/core-transport/src/lib.rs:32-39`, `:118`) and the state
  `NeedsUpdate` of the app's client (`tor.rs:172`). The exit itself stays (the Owner's choice "Р19 б",
  D-199): the app can close once, and once more if arti's directory cache is lost. The exit was not
  observed (PR #274: not run); the mapping to `NeedsUpdate` is tested (`lib.rs:172-236`).
- **Provider, isolation, dependencies.** ring is installed as the process's rustls provider once, first in
  `ArciumCore::new` (`crates/mobile-ffi/src/lib.rs:49`, `:88`). Every stream a `TorConnector` opens is in
  one isolation group of its own (`crates/core-transport/src/connector.rs:58`, `:77`). arti's
  `onion-service-service` feature is off (`crates/core-transport/Cargo.toml:16`). `mobile-ffi` depends on
  `core-transport` again, so arti and `rsa` are in the Android library; the RUSTSEC-2023-0071 entry gives the
  reasoning the Owner accepted (D-192) and a grep-level check that the client side uses RSA public keys only
  (`.cargo/audit.toml:13-42`).
- **State for the app.** `tor_state()` (`tor.rs:88`, `TorState` at `:66`) answers at once: not started,
  starting, running, needs an update, or failed.

**Tests.** `tests::relay_onion` (5) and `network::tor::tests` (10) in `mobile-ffi`, over stand-ins for the
Tor client and its stream, and `connector::tests::each_connector_has_an_isolation_group_of_its_own` in
`core-transport`; #274's tests in `core-transport/src/lib.rs` (`:172-236`). PR #275's description lists the
mutations each catches (24 in all).

**Runtime evidence.**
- PR #275's description, at its head `79aba81`: `cargo test --workspace --locked` → exit 0, `mobile-ffi`
  `test result: ok. 328 passed; 0 failed; 1 ignored`, every binary `0 failed`; `cargo clippy --workspace
  --locked -- -D warnings` → exit 0.
- CI (GitHub check runs of #275): all 9 check runs success on the head `79aba81`.
- Reviews of #275: two rounds, each by one fresh-context agent with both `engineering-code-review` and
  `arcium-security-review`: no CRITICAL or HIGH; one MEDIUM and one LOW in the first round, both fixed before
  the merge. The Reliability System review (Arcium 2): report APPROVE with three nits, R275-1 to R275-3, on
  reliability-system branch `review/pr-275` (`workspace/reviews/PR-275-79aba81.md`), as the Builder read it
  from the review chat (continuity D-205; not on this repository's GitHub). It ran no test: its build failed
  in its sandbox. R275-1 and R275-2 are addressed by PR #277, an open draft at this snapshot. *(Note 2026-11-28: PR #277 is merged; see "Update 2026-11-28: Tor route in Settings and core fixes".)*
- Not run anywhere: a real Tor network (no test or CI job bootstraps arti), arti's process exit, Tor on
  Android (bootstrap time, battery, arti's permission check of `filesDir/tor`), the library's size.

| ID | Status at `2578962` | Evidence (`main` @ `2578962`) | Label |
|----|---------------------|-------------------------------|-------|
| **F-15** (Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir`) | Note only; status unchanged: (a) **NOT-FIXED (design)**, no code since PR #157; (b) **FIXED** (PR #265); `NEEDS-HOME`. The Tor transport now has a caller in the app's core: a relay at an onion address goes only through it, with no direct fallback (PR #275). The Kotlin stub `ArciumCore.startTorTransport()` still throws at this snapshot (PR #276, open, removes it). *(Note 2026-11-28: removed by PR #276; see "Update 2026-11-28: Tor route in Settings and core fixes".)* | `crates/mobile-ffi/src/network.rs:679-686`; `network/tor.rs:197`, `:205-213` | `SOURCE_VERIFIED`, `RUNTIME_VERIFIED` (stand-in tests); a real Tor network and Android `NOT_VERIFIED` |
| **D-008** (lead of 2026-11-06; FIXED by PR #137) | Note only. The bound is unchanged (`BOOTSTRAP_TIMEOUT` = 120 s) and is now on a production path: the first connection to an onion relay waits for it (`TorConnector::bootstrap`; `TorTransport::new` still has no caller). A start that fails is not retried for 60 s, except one that panics (R275-1). *(Note 2026-11-28: since PR #277 a start that panics is not retried for 60 s either; see "Update 2026-11-28: Tor route in Settings and core fixes".)* | `crates/core-transport/src/lib.rs:20`; `crates/mobile-ffi/src/network/tor.rs:40`, `:213` | `SOURCE_VERIFIED` |
| **R-4** (no time bound on a relay operation or a sync round; FIXED by PR #145, with remainders) | Note only; status unchanged. The unbounded name lookup lies in `TcpConnector::connect`, which an onion relay never uses (no lookup on that path); a relay at an ordinary address still has it. | `crates/relay/src/client.rs:205-211`; `crates/mobile-ffi/src/network.rs:682-685` | `SOURCE_VERIFIED` |

Not rows:

- The step-4.1 notes of the "arti 0.48 in core-transport" and "Tor connector in core-transport" sections
  (the process exit, the provider, `rsa`, no `TcpConnector` for an onion host, a timeout suited to Tor,
  stream isolation) are answered above; each has a dated note pointing here.
- Places that say the Tor transport has no caller or is not wired (the F-15 row, the D-008 lead, the
  2026-11-20 F-15 and D-008 rows and its paragraph on `rsa`, the 2026-11-24 sections and their F-15 and R-4
  rows, the 2026-11-25 R-4 paragraph, item 6 of "Prioritized remaining work") keep their snapshots; each has
  a dated note pointing here.
- The places that cite the Kotlin `startTorTransport` (the F-12 row, the D-008 lead, the 2026-11-20 D-008
  row and the "arti 0.48 in core-transport" section) stay true at this snapshot in what they say (the stub
  throws, `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt:266-272`; F-12's own anchors
  predate later edits of that file); PR #276, open, removes the stub, and they get notes once it lands.
  *(Note 2026-11-28: PR #276 is merged and the notes are in place; see "Update 2026-11-28: Tor route in Settings and core fixes".)*
- Arcium 2's R275-1 (a start that panics skips the 60 s pause) and R275-2 (a malformed development address
  goes the direct way) are review notes, not rows here; PR #277, an open draft, addresses both.
  *(Note 2026-11-28: PR #277 is merged; see "Update 2026-11-28: Tor route in Settings and core fixes".)*

---

## Update 2026-11-28: Tor route in Settings and core fixes (`main` @ `cdbf9d3`)

**Snapshot:** `main` @ `cdbf9d3e08d5233b71eec8ad4bbd24407b3f45ed`. The code is in the merges of PR #276
(head `cdad62d`, merged as `df33691`, parents `2578962` and `cdad62d`) and PR #277 (head `14a1cef`, merged
as `a7166fe`, parents `df33691` and `14a1cef`), on the Owner's choice "Мерж 276", "Мерж 277" (continuity
D-209). `df33691` has the tree of #276's head; `a7166fe` has the tree of #277's head plus #276's files, so
#277's own evidence below was taken on `2578962`, without #276. The merges after them, PR #278 (the 2026-11-27 section of this file) and PR #279 (the security-review
checklist under `.claude/`), change no code. This section covers #276 and #277 only. Each `path:line` below
was re-read at `cdbf9d3`.

**No status change.** Notes on F-12, F-15 and D-008.

**What changed.**
- **What Settings says (#276).** Under the saved relay, Settings says "Without Tor: the relay sees your IP
  address." or "Through Tor: the relay does not see your IP address.", the latter followed by the state of
  the process's Tor client once it has been read (`routeStatus` and `torStatus`,
  `android/app/src/main/kotlin/com/arcium/messenger/ui/settings/RouteText.kt:13-31`, the state at `:15-16`;
  the line at `ui/settings/SettingsScreen.kt:165-169`). Which one is chosen by `relayGoesThroughTor`
  (`android/app/src/main/kotlin/com/arcium/messenger/messaging/RelayRules.kt:54-74`): the core's onion rule
  (`is_onion`, `v1_host`, `crates/mobile-ffi/src/network/tor.rs:45`, `:54`; for V2 the host of
  `RelayAddress::parse`, `crates/relay/src/address.rs:66-70`) written again in Kotlin, for the label only; it
  does not repeat `check_v1` (below). The core alone decides the route, as at `2578962`. While the saved relay goes through Tor, the
  screen reads `tor_state()` every second on `Dispatchers.IO` inside `repeatOnLifecycle(STARTED)`
  (`SettingsScreen.kt:88-98`), so not while the app is in the background.
- **The Kotlin Tor stub is gone (#276).** `ArciumCore.startTorTransport()`, which threw
  `NotImplementedError` and had no caller, is removed. `torState()`
  (`android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt:269`) passes the core's state
  through; `submitPsiQuery` (`:255-261`) still throws.
- **A start that panics pauses too (#277; Arcium 2's R275-1).** `Shared::get_or_start` catches a panic in
  the start as `TransportError::Bootstrap("the start panicked")` (`crates/mobile-ffi/src/network/tor.rs:153-154`):
  the state is `Failed`, and connections fail at once for `RETRY_AFTER` (60 s, `:40`), as after any failed
  start (`:147-151`, `:176-178`).
- **A malformed development address is tried nowhere (#277; R275-2).** A V1 string is a relay only when
  `check_v1` accepts it (`crates/mobile-ffi/src/network.rs:172-203`, applied in `Relay::parse`,
  `:150-155`): a decimal port from 1 to 65535, and a host that is an IPv6 address in brackets or a DNS name
  of ASCII labels. Anything else is `Relay::Invalid` (`:134`): every connection fails with "invalid relay
  address: …" (`:734`) and nothing is tried, neither Tor nor the direct path. So a name such as
  `x.onion:1:7700` or `x.onion-:7700`, which a debug build saves, no longer reaches this device's resolver
  (`x.onion :7700` the app already refused, `RelayRules.kt:148`). The app accepts a V1 string in a debug
  build only (`RelayRules.kt:35`; `BuildConfig.DEV_RELAY_ALLOWED`, true only in `debug`,
  `android/app/build.gradle.kts:28-33`, read at `messaging/RelaySettings.kt:26`, `:37`).
- **The relay's start (#277).** `restrict` (`crates/relay/src/disk.rs:71-91`) sets owner-only permissions on
  the database's `-wal` and `-shm` files and treats one that is already gone as nothing to do (`:85-86`).
  Before, it checked that each existed and then set its permissions, and a file removed in between by
  another connection's close failed the relay's start: the cause of a rare failure of
  `a_relay_with_a_database_keeps_mailboxes_and_bundles_across_restarts`, shown in PR #277 by widening that
  gap with a sleep.

**Tests.**
- #276: `RelayRulesTest.onlyARelayAtAnOnionAddressGoesThroughTor` and `RouteTextTest` (3) on the JVM;
  `TwoDeviceMessengerTest.switchesToTheEncryptedRelay` reads the direct label on the emulator
  (`android/app/src/androidTest/kotlin/com/arcium/messenger/e2e/TwoDeviceMessengerTest.kt:202`).
- #277: `network::tor::tests::a_start_that_panics_fails_and_pauses_like_any_failed_start` (`tor.rs:418`),
  `network::tests::a_development_relay_address_is_tried_only_when_well_formed`
  (`crates/mobile-ffi/src/network/tests.rs:147`),
  `tests::relay_onion::a_malformed_development_address_is_tried_on_no_path`
  (`crates/mobile-ffi/src/tests/relay_onion.rs:251`), and in the relay
  `disk::tests::a_side_file_left_open_is_restricted_and_a_missing_one_is_no_error` (`crates/relay/src/disk.rs:366`),
  which checks the permissions and a missing file and passes on the old code too: no test holds the race fix
  (PR #277's mutation D3).
  Each PR's description lists the mutations its tests catch.

**Runtime evidence.**
- PR #276's description, at its head `cdad62d`: the two JVM test classes, run outside the app's Gradle
  build with Kotlin bindings generated from the head's library (no Android SDK in the Builder's sandbox):
  `RelayRulesTest` `tests="9" skipped="0" failures="0" errors="0"`, `RouteTextTest` `tests="3" skipped="0"
  failures="0" errors="0"`.
- PR #277's description, at its head `14a1cef`: `cargo test --workspace --locked` → exit 0, `mobile-ffi`
  `test result: ok. 330 passed; 0 failed; 1 ignored`, `relay` `68 passed; 0 failed`, every binary `0 failed`;
  `cargo clippy --workspace --locked -- -D warnings` → exit 0.
- CI (GitHub check runs): all 9 success on #276's head `cdad62d`, all 9 on #277's head `14a1cef`. After the
  merges, all 10 push runs on `df33691`, `a7166fe`, `705057a` and `cdbf9d3` success, among them Android CI on
  `df33691` and the emulator instrumentation and two-emulator runs on `df33691` and `a7166fe`; those on
  `a7166fe` are the first CI of #276 and #277 together.
- Reviews. #276: one fresh-context agent with `engineering-code-review`, `arcium-security-review` and
  `android-uniffi-bridge`, at `c563453`: the security review found nothing above INFO; the engineering review
  graded one item a warning (Tor's state was read while the app was in the background) and named test gaps
  (three mutations survived). Its items were fixed in `cdad62d`, except the security checklist's "no Tor"
  line, which needed the Owner's word and was changed by PR #279; no fresh agent read `cdad62d` again
  (continuity D-207). #277: one fresh-context agent with both review skills, at `fcc274e`: no security
  defect; one warning (the pause was not pinned) and INFO items. In `14a1cef` the pause test was pinned,
  `check_v1`'s host rule was narrowed to DNS labels and comments were fixed; no fresh agent read `14a1cef`
  again (PR #277's description; continuity D-208). Two items stay in PR #277's Limits: strings the core
  refuses but the app saves (below), and that `restrict` ignores only `NotFound`, which no test pins. Neither had a Reliability System
  (Arcium 2) review: the Owner chose to merge without one (continuity D-209).
- Not run anywhere: a real Tor network, Tor on a phone, the Settings screen with a relay at an onion address
  (no test drives it), and that the polling stops in the background.

| ID | Status at `cdbf9d3` | Evidence (`main` @ `cdbf9d3`) | Label |
|----|---------------------|-------------------------------|-------|
| **F-12** (Kotlin crypto stubs return plaintext as "ciphertext"; FIXED) | Note only; status unchanged. `startTorTransport` is removed (PR #276), so the row's anchor for it is stale. The property the row records still holds: `submitPsiQuery` throws, and the new `torState()` returns the core's state, not a stand-in value. | `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt:255-261`, `:269` | `SOURCE_VERIFIED` |
| **F-15** (Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir`) | Note only; status unchanged: (a) **NOT-FIXED (design)**; (b) **FIXED** (PR #265); `NEEDS-HOME`. Settings now labels whether the saved relay is reached through Tor, by a Kotlin copy of the core's rule, and shows Tor's state (PR #276); the route is the core's, unchanged. The Kotlin stub is gone. A start that panics now pauses like any failed start, and a malformed development address is tried on no path (PR #277). | `RouteText.kt:13-31`; `RelayRules.kt:54`; `crates/mobile-ffi/src/network/tor.rs:153-154`; `crates/mobile-ffi/src/network.rs:150-155` | `SOURCE_VERIFIED`, `RUNTIME_VERIFIED` (JVM and stand-in tests; the direct label on the emulator); a real Tor network, Tor on Android and the screen with an onion relay `NOT_VERIFIED` |
| **D-008** (lead of 2026-11-06; FIXED by PR #137) | Note only. The 60 s pause after a failed start now also follows a start that panics (PR #277): the exception in the 2026-11-27 section no longer holds. | `crates/mobile-ffi/src/network/tor.rs:40`, `:153-154` | `SOURCE_VERIFIED`, `RUNTIME_VERIFIED` (stand-in test) |

Not rows:

- The places that cite the Kotlin `startTorTransport` (the F-12 row, the D-008 lead, the D-008 row of "D-008
  and D-010: fixed or decided", the 2026-11-20 D-008 row, the opening paragraph and the F-15 row of "arti 0.48
  in core-transport", the 2026-11-27 F-15 row and its paragraph on these places)
  keep their snapshots; each has a dated note pointing here.
- The places in the 2026-11-27 section that say a start that panics skips the pause, that a relay at any
  host other than an onion name is reached directly, or that #277 is open (its "Bounds" item, its routing
  sentence, its review item, its D-008 row and its paragraph on R275-1 and R275-2), keep their snapshot; each has a dated note pointing here. Arcium 2's R275-3 (the isolation test reads arti's `Debug`
  text) is left as it is.
- One rule in two places: `relayGoesThroughTor` repeats the core's onion rule for the label. A later change
  to one must be made in both; `RelayRulesTest.onlyARelayAtAnOnionAddressGoesThroughTor` holds the Kotlin
  copy to the core's host cases, not to the core itself.
- `check_v1` refuses some development strings that the app's own check (`devHostPort`,
  `RelayRules.kt:143-150`) saves, such as `x.onion:1:7700`, a host with `_` or a scoped IPv6 address: such a
  relay is saved, and Settings labels it by the Kotlin rule, which knows nothing of `check_v1`, either way:
  `x.onion:1:7700` reads "Without Tor", `[x.onion]:7700` "Through Tor" (`RelayRulesTest.kt:145` pins it as
  Tor, `crates/mobile-ffi/src/network/tests.rs:175` as refused). Every round then fails with "invalid relay
  address" (debug builds only; nothing is sent).
- The relay's `restrict` change (above) is not a finding.

---

## Prioritized remaining work

For new work, see "Next engineering tasks (2026-11-06)" above; this list is kept as history. Regenerated 2026-09-29 from the tables above; the 2026-07-19 list is superseded. Order is
the reviewer's suggestion, not a commitment, and every item needs its own task, its own PR
and an explicit owner instruction (crypto and protocol changes are never bundled).

1. **F-3** (PSI padding convention) is done, merged in PR #118 (`ed5737c`); the circuit hash
   it set, `dd3bda7c…b919`, is what a devnet deploy would freeze (no deployment is
   established).
2. **F-4**, **F-14** server-set anchoring and the result-delivery gap — with the MXE deploy;
   behaviour is `NEEDS-HOME`.
3. **F-5** (pin actions by commit SHA, version `cargo-audit`, retire the archived release
   actions in `monthly-backup.yml`) is done, merged in PR #116 (`fbf7243`). **H-10** (pin
   `Cargo.lock`) is done by A-3.7, merged in PR #114.
4. **F-9** is done for the store's own master key, merged in PR #120 (`e0e825c`): identity
   load errors fail closed and identity creation is create-only. A wrong, lost or replaced
   master key still reads as "no identity" (`MasterKeyProvider` creates a new key when its
   blob is missing); that path needs its own owner-scoped task (see F-9, scope).
   *(Updated 2026-11-06.)* That task is done for Android start-up, merged in PR #133 (`090bb17`). A missing,
   corrupted or unusable blob with an existing store now blocks start-up without creating a key or an
   identity. Still open: a recovery flow (none exists), backup/transfer and physical-device verification,
   and the unchanged Rust-level `Ok(None)` for a different key (see "Update 2026-11-06: master-key loss at
   start-up").
5. **H-2, H-6, H-7** the remaining memory-hygiene items (H-1, H-3, H-4, H-5 were closed by A-3.1, merged in PR #105; H-11 and H-12 by A-3.2, merged in PR #106; H-13 by A-3.3, merged in PR #107; H-14 by A-3.4, merged in PR #108; H-15 by A-3.6, merged in PR #112), and **H-9**, whose upstream-supported partial hardening (`hmac 0.13.0` and `sha2 0.11.0` with `zeroize`; `hkdf 0.13.0` benefits transitively) is done by A-3.5, merged in PR #110 (`f72043e`); further H-9 work requires a separate owner-scoped investigation of the remaining upstream/local residuals listed in H-9, without selecting a technical solution here.
6. **F-15** and **F-16** at devnet integration: the Tor transport is unwired, and the PSI
   client's nonce and low-order-point handling need a production caller's decision. *(Updated 2026-11-27: the Tor transport is wired for a relay at an onion address, PR #275; see "Update 2026-11-27: Tor for onion relays".)*
7. **H-8** verify release-build wiping on a device, when a device is available.

---

*This tracker is a documentation artifact. Its statuses are a snapshot at `main` @ `087b9c8`
on 2026-09-29, plus the A-3.1 rows (H-1, H-3, H-4, H-5), which describe PR #105, merged into `main`
as `6266c0b`, the A-3.2 rows (H-11, H-12), which describe PR #106, merged as `e5331ed`, the
A-3.3 row (H-13), which describes PR #107, merged as `a96d72b`, the A-3.4 row (H-14), which
describes PR #108, merged as `5d61d5a`, and the A-3.5 row (and H-9's partial status), which describes PR #110, merged as
`f72043e`, and the A-3.6 row (H-15), which describes PR #112, merged as `62fbf55`, and the A-3.7 row (H-10), which describes PR #114, merged as `8565875`, and the F-5 row, which describes PR #116, merged as `fbf7243`, and the F-3 row, which describes PR #118, merged as `ed5737c`, and the F-9 row (with the cross-reference added to X-1), which describes PR #120, merged as `e0e825c` — except **F-17**, whose closure record dates from
`main` @ `1a7b1904` (2026-07-28) with the re-check note above. Re-verify a row against the
source at your own target SHA before relying on it, and do not read a `FIXED` here as a
statement about anything the row does not name. A-3 itself stays **PARTIAL** (see that row).*

*The "Reconciliation 2026-11-06" section, its rows A-4 and X-4, note N-3 and the cross-reference notes dated 2026-11-06 in F-9, F-10 and F-15 describe `main` @ `7455da8`.*
*The "Update 2026-11-06: master-key loss at start-up" section and the 2026-11-06 notes in F-9, X-1 and item 4 of the list below it describe `main` @ `090bb17`.*
