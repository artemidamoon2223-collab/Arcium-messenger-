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
| **F-12** | LOW | Kotlin crypto stubs return plaintext as "ciphertext" | **FIXED** *(corrected 2026-09-29)* | `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt` no longer contains `ratchetEncrypt`, `ratchetDecrypt` or `x3dhInit` (a search of `android/app/src/main` finds none). Messaging methods forward to the generated UniFFI calls (`:63-250`); `submitPsiQuery` (`:257-263`) and `startTorTransport` (`:270-276`) throw `NotImplementedError` instead of returning a value that could be mistaken for a result. This is a static read; no Android tooling was used for this row (the Android CI jobs exercise the wrapper, but their results are not cited here). |
| **F-13** | INFO | X3DH: SPK signature lacks domain separation; OPK single-use unenforced | **FIXED** *(corrected 2026-09-29)* | (a) Domain separation: see F-2 (`x3dh.rs:17`, `:69-82`); a raw-key signature does not verify (test `signatures_from_other_contexts_are_rejected`). (b) One-time-prekey single use: `accept_first_message` (`mobile-ffi/src/lib.rs:849-927`) takes the one-time prekey (`:879`), rotates the prekey record (`:880-883`) and replaces it through a conditional `SideWrite::replace` (`:905-911`) in the same transaction that promotes the session; a lost race is `OneTimePrekeyUnavailable` (`:922`); `check_answerable` (`:824-838`) refuses a wrong id or a stripped one-time prekey. Tests `matching_one_time_prekey_is_consumed_and_replaced`, `replaying_an_accepted_handshake_is_rejected_and_changes_nothing`, `concurrent_first_messages_create_one_session_and_consume_the_prekey_once`, `stripping_the_one_time_prekey_is_refused_rather_than_downgraded`, `wrong_one_time_prekey_id_does_not_consume_the_current_one` pass. **Scope:** single use is enforced only where the responder holds a one-time prekey; a handshake answered without one has no replay property (`mobile-ffi/src/lib.rs:769-772`). |
| **F-14** | INFO | On-chain placeholders and result-delivery gap (pre-deploy) | **NOT-FIXED (pre-deploy)** · behavior `NEEDS-HOME` | `arcium-psi/programs/arcium-psi/src/lib.rs:7` — placeholder `declare_id!("PSiArc1um111…")`. The callback verifies the output signature (`:133-136`) but only `msg!`-logs the client's encryption key (`:141-144`); the match vector is written to no account or event. Legacy `submit_query` (`:21-32`) still ignores `encrypted_contacts` (`:30`). Access control on the implemented instructions read sound statically (payer-seeded `init_user` PDA `:153-158`, `has_one = owner` `:167`, monotonic nonce `:27`); MXE authority semantics are `NEEDS-HOME`. |
| **F-15** | INFO | Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir` | **NOT-FIXED (design)** · `NEEDS-HOME` *(scope clarified 2026-09-29)* | (a) `android/app/src/main/kotlin/com/arcium/messenger/network/SolanaClient.kt:7` uses `BuildConfig.SOLANA_RPC_URL` directly (clearnet). (b) `crates/core-transport/src/lib.rs:23-24` — `new(_state_dir)` ignores its argument and uses `TorClientConfig::default()`. **Scope:** the review wrote "messaging rides Tor (arti)"; that is not true of current code. `core-transport` is a `mobile-ffi` dependency in `Cargo.toml` but no source in `crates/` calls it, and `docs/NET-MESSAGING.md` records Tor as a stub and future work (`:25`) and states the relay path has "no anonymity and no Tor" (`:138-139`, `:231`). So F-15 covers the unwired Tor transport and the PSI/Solana RPC path only; the relay path's lack of anonymity is a documented design limit, not something this row tracks or claims to fix. **Cross-ref (2026-11-06, `7455da8`):** `TorTransport::new` also has no bootstrap timeout and still has no production caller (D-008 in "Reconciliation 2026-11-06"). Status unchanged. |
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
| **A-3.5** | Upstream-supported partial hardening of third-party secret state (ARCIUM-H9-UPSTREAM-MEMORY-HARDENING-A3.5): `hmac 0.13.0` and `sha2 0.11.0` enable their `zeroize` features; `hkdf 0.13.0` has no `zeroize` feature of its own and benefits transitively through its HMAC context's feature-enabled SHA state and digest block buffer. The storage KDFs now hold and wipe the HKDF pseudorandom key. **Partial:** H-9 becomes PARTIALLY_FIXED, not FIXED. A-3 itself stays PARTIAL (H-9 residuals and others below); A-3.1…A-3.4 are unchanged by this stage. | **FIXED — merged** in PR #110 (merge commit `f72043e4c92ccee54e308709091139871bef6359`) — verified at code commit `1fe320c` (later commits in the PR, up to its final HEAD `cb71e9e`, changed only this file) | **Graph** (`cargo metadata` on the A-3.5 tested tree; at that time the root lockfile was untracked, see H-10 and A-3.7): `hmac 0.13.0` (feature `zeroize`), `hkdf 0.13.0` (no features), `sha2 0.11.0` (`zeroize`, `alloc`, `default`, `oid`) over `digest 0.11.3` (`zeroize`), `block-buffer 0.12.1` (`zeroize`), `crypto-common 0.2.2`, `hybrid-array 0.4.15`, `zeroize 1.9.0`; declared at `Cargo.toml:20-22`. At `31f7915` it was `hmac 0.12.1`, `hkdf 0.12.4`, `sha2 0.10.9`, `digest 0.10.7`, none with `zeroize`. Direct users: `core-crypto` (all three), `core-storage` (`hkdf`, `sha2`), `core-protocol` and `mobile-ffi` (`sha2`). **Arcium-owned change:** the HMAC key constructor moved to `KeyInit::new_from_slice`; `hmac_tag` (`crates/core-crypto/src/ratchet.rs:416-421`) borrows the `CtOutput` until it is copied into the wiping destination and does not call `into_bytes`, which takes `&self` in `digest 0.11` and would clone the tag (`digest-0.11.3/src/mac.rs:207-209`). Before A-3.5, this Arcium path already explicitly wiped the caller-owned output after copying it; the new path preserves that protection through `CtOutput`'s drop cleanup and avoids the ordinary clone the new API would make; the three storage KDFs take the HKDF pseudorandom key from `extract` and wipe it (`KeyMaterial::hkdf`, `crates/core-storage/src/lib.rs:298-302`) where `Hkdf::new` dropped it unwiped. The existing `extract` + wipe in `kdf_rk`, `derive_root` and `combine_secrets` is kept. No `unsafe`, no custom or copied crypto, no fork or patch. **Cleanup provided by the upgraded dependency graph** (drop cleanup in the resolved versions, sources read; new in A-3.5 are the owned `Sha256` state cleanup, the `BlockBuffer` cleanup and the cleanup of the bytes owned by `CtOutput` in the new API — together with the Arcium-owned changes above, the avoided `into_bytes(&self)` clone and the explicit storage PRK wipe; the caller-owned output buffer of `hmac_tag` was already explicitly wiped before A-3.5): the `Sha256` hasher and `Sha256VarCore` state (`sha2-0.11.0/src/block_api.rs:89-101`, only with `sha2/zeroize`), the `BlockBuffer` (`block-buffer-0.12.1/src/lib.rs:424-442`) and the bytes owned by HMAC's `CtOutput` (`digest-0.11.3/src/mac.rs:241-253`), both via `digest/zeroize`. The owned inner and outer SHA state and block buffer of a keyed `Hmac<Sha256>`, including those fields in each HMAC context cloned by HKDF expand, wipe through field drop glue (`Hmac` has no `ZeroizeOnDrop` of its own). HKDF's ordinary `T(n)`, `output` and `prev` locals are not covered. Each direct `Sha256` has the same state/buffer cleanup; `record_digest` hashes the session checkpoint record, which holds ratchet secrets. `hmac/zeroize` alone does not wipe the hash state: it reaches only `digest`. **Bytes unchanged:** golden outputs captured from the production functions at `31f7915` before the change and pinned in `ratchet/golden.rs`, `x3dh/golden.rs` (with and without an OPK), `hybrid/golden.rs`, `core-storage/src/golden.rs` (subkey, key-name hash, key-name encryption subkey) and `durable/golden.rs` (`record_digest`, lengths around the block boundary); each also equals an independent recomputation with Python's `hmac`/`hashlib` (run once in the session, the script is not committed); RFC 4231, RFC 5869 and FIPS 180-4 vectors (`hash_contract.rs`); the earlier fixtures of previous implementations (a ratchet conversation with skipped keys and a DH step, checkpoints, the legacy databases of `legacy_upgrade`) still pass. **Storage:** a database written by the base commit with a fixed key (10 values, several namespaces) was opened by this tree — file bytes unchanged by the read, every value and namespace listing identical — then written to, and the base build read the result (RUNTIME_VERIFIED, scratch harness, not committed). **Pins:** `sha256_hasher_is_wiped_on_drop`, `keyed_hmac_parts_and_its_tag_are_wiped_on_drop` (compile only with the features), `the_hkdf_key_is_always_wiped_and_the_hmac_tag_is_never_copied` and `the_hkdf_key_is_always_wiped` (source text: spelled forms only), `tests/feature_graph.rs` (`cargo tree --offline`: the features and the lines per crate). Temporary controls: no `hmac/zeroize` — caught by `feature_graph` only (the type pins cannot see it, because `sha2/zeroize` enables the same `digest` feature); no `sha2/zeroize` — caught by the type pins and `feature_graph`; `Hkdf::new` restored, `into_bytes` added — caught by the source guards; a clone spelled `as_bytes().clone()` — **not caught**; a changed HKDF info, salt or HMAC tag — caught by the goldens. **Limits:** cleanup covers the named hash-state, buffer and `CtOutput` owners, not every secret-derived value; H-9 lists the remaining ordinary locals. Source-visible absence of cleanup does not establish physical recoverability after return. Green tests and a successful build do not show that memory is erased on a device. The old `hmac 0.12.1`, `hkdf 0.12.4` and `sha2 0.10.9` remain in the graph for third-party consumers (see H-9). |
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
| **H-9** | LOW · **PARTIALLY_FIXED** (A-3.5, merged in PR #110 (`f72043e`)) | Secret-derived state inside `hmac`, `hkdf` and `sha2`. **Before A-3.5** (`hmac 0.12.1`, `hkdf 0.12.4`, `sha2 0.10.9`) these crates provided no internal zeroization or drop cleanup. Arcium's `hmac_tag` already explicitly wiped its caller-owned output after copying it. **After A-3.5** (`hmac 0.13.0` and `sha2 0.11.0` with `zeroize`; `hkdf 0.13.0` benefits transitively and has no `zeroize` feature of its own; exact graph in A-3.5) the owned SHA state, block buffer and `CtOutput`-owned HMAC tag bytes wipe on drop, and Arcium explicitly wipes the caller-owned PRK returned by `Hkdf::extract` at every audited Arcium extract call site (`kdf_rk`, `derive_root`, `combine_secrets` and, new in A-3.5, the three storage KDF derivations). This covers that returned PRK buffer only: not internal HMAC/HKDF state, not other PRK-derived copies, not moved-from locations, and not HKDF's `T(n)`, `prev` and `output` locals (residuals below). **Source-visible residuals (SV, audited stock versions):** ordinary locals without cleanup: the normalised key block and its `⊕ ipad` / `⊕ opad` variants (`hmac-0.13.0/src/utils.rs:9-32`, `block_api.rs:53-69`); the inner digest `hash` in `finalize_fixed_core` (`block_api.rs:81-90`); the ordinary `CtOutWrapper::full_res` digest copy, copied into the final output without local cleanup (`digest-0.11.3/src/block_api/ct_variable.rs:103-116`); HKDF's `T(n)` blocks, `prev` and `output` in `expand_multi_info` (`hkdf-0.13.0/src/lib.rs:135-162`); compression message schedules and working locals in software/hardware backends (e.g. `sha2-0.11.0/src/sha256/soft/unroll.rs:46`, `x86_sha.rs:46`, `aarch64_sha2.rs:13`). Each HKDF expand HMAC context clone has cleanup of its owned SHA state and block buffer, not of these ordinary output locals. **Inferred persistence (INF):** moved-from stack slots, register spills and stale stack copies may retain material, including `Output` moved through `Mac::finalize` (`digest-0.11.3/src/mac.rs:97-99`) and out of `Hkdf::extract` (`hkdf-0.13.0/src/lib.rs:61-65, 117-121`). Arcium wipes the returned PRK owner; persistence in other locations after return is inferred, not observed. Source-visible absence of cleanup does not prove physical recoverability. **Not verified (NV):** actual post-operation Android/device memory contents, compiler/register erasure and physical RAM behaviour. Also: `hkdf` has no `zeroize` feature of its own and relies on `hmac`/`sha2` features Cargo unifies, and `hmac/zeroize` alone reaches only `digest`, so the hash-state wipe depends on `sha2/zeroize` (pinned by `feature_graph` and `hash_contract`, see A-3.5); before A-3.7 the untracked root lockfile allowed a fresh compatible resolution — patch releases within the declared semver ranges and changes to transitive versions — so the exact audited implementation source was not permanently pinned (H-10); since A-3.7 the root `Cargo.lock` is tracked, root CI and native builds use it with `--locked`, and a dependency-version change needs an explicit reviewed lockfile diff. This does not pin the toolchain or compiler, nor what a future dependency release would contain. **Old lines still in the graph, for other consumers:** `hmac 0.12.1` (`hkdf 0.12.4`, `rfc6979`, `tor-proto`), `hkdf 0.12.4` (`tor-proto`) and `sha2 0.10.9` (`ed25519-dalek`, `p256`/`p384`/`p521`, `rsa`, `ssh-encoding`, `ssh-key`, `tor-llcrypto`), with no `zeroize` feature. They are not among the audited call sites, but `ed25519-dalek` expands the Ed25519 signing key with `sha2` 0.10's `Sha512` (`ed25519-dalek-2.2.0/src/signing.rs:23, 318`), and Arcium generates that key (`crates/mobile-ffi/src/lib.rs:207`): recorded, not fixed. **Standalone production `Sha256` uses:** only `record_digest` (`core-protocol/src/durable.rs:309`) hashes secret-bearing input (the session checkpoint record) — its hasher is now wiped; the others hash public or non-key data (`spk_id`, `local_session_handle`, `message_id`, the handshake dedup key, the contact-card fingerprint, `hash_contact` over a phone number) and their outputs are intentionally kept. The stock upstream versions audited here leave the listed residuals. Complete safe-Rust source-level remediation has not been established and has not been proven impossible (**UNCERTAIN**); further work requires a separate owner-scoped investigation, with no technical solution selected here. See F-8. | `Cargo.toml:20-22`; `crates/core-crypto/src/ratchet.rs:388-421`, `x3dh.rs:200-223`, `hybrid.rs:158-188`; `crates/core-storage/src/lib.rs:298-302` | SV (named owner cleanup and source-visible ordinary locals without cleanup in the resolved versions); INF (persistence of moved-from stack/register copies); RUNTIME_VERIFIED (byte compatibility, see A-3.5); NV (post-operation device memory, compiler/register erasure and physical RAM behaviour) |
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
  hard-codes `"TODO.onion"` (`:30`).
- *Production caller.* None.
  - `mobile-ffi` lists `core-transport` as a dependency (`crates/mobile-ffi/Cargo.toml:16`),
    but nothing under `crates/mobile-ffi/src` names `core_transport` or `TorTransport`
    (`grep`, no match).
  - The Kotlin `startTorTransport` throws `NotImplementedError`
    (`android/.../ffi/ArciumCore.kt:263-269`).
  - Today the missing timeout cannot block any shipped path (SOURCE_VERIFIED by the absence
    of callers).
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
| **D-008** | `TorTransport::new` had no bootstrap bound: arti keeps retrying its directory download, so an unreachable Tor network made `new` wait for hours. | **FIXED — merged** in PR #137 (merge commit `04968d3`). Scope: the bootstrap only. | `BOOTSTRAP_TIMEOUT` = 120 s (`crates/core-transport/src/lib.rs:15`); `new` calls `new_within` with it (`:35-37`); `bootstrap_within` wraps the bootstrap in `tokio::time::timeout` and maps a timeout to `TransportError::Bootstrap` (`:59-71`). Tests `bootstrap_within_times_out_on_a_bootstrap_that_never_finishes`, `…_reports_a_bootstrap_error_as_bootstrap`, `…_returns_a_finished_bootstrap` pass (`RV`). **Not changed:** `state_dir` is still ignored (`_state_dir`, `:40`), so **F-15(b) stays open**; the transport is still not called by the app (`ArciumCore.kt:263-269`, F-15). `new_fails_gracefully_without_tor` stays `#[ignore]` (`:166`) and was not run here (`NV`). |
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
| **R-4** (no time bound) | **FIXED — merged** in PR #145 (merge `997c416`, run 43332361616). One relay request at most 30 s, one round at most 120 s of relay requests. | `REQUEST_DEADLINE` (`crates/relay/src/client.rs:35`), `ROUND_BUDGET` (`crates/mobile-ffi/src/network.rs:208`). A round cut by the budget reports `BUDGET_EXHAUSTED`, which is not a network error, and the next round continues where the passes stopped (`:243`, `Resume` `:154`) (review findings F-145-1 and F-145-2, fixed before the merge). **Remaining:** the DNS lookup in `Connection::connect` (`crates/relay/src/client.rs:87`) is not bounded; below about 35 KiB/s a full page cannot arrive within 30 s (no adaptive paging). | `SV`, `RV` |
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
   client's nonce and low-order-point handling need a production caller's decision.
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
