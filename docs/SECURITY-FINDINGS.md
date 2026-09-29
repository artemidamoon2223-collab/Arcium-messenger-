# Security Findings Tracker — Arcium Messenger

**Reconciled against `main` @ `087b9c8c550e0b96d7b451d3f953e4860cd7765c` (the merge of PR #103), 2026-09-29.**
The previous snapshot was `main` @ `492c5d1f6385ddf698cf210ec29f0d67fb6a1d8f`, 2026-07-19.
F-17 additionally keeps its own 2026-07-28 closure record, with a re-check note at the end of it.

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
  is git-ignored (`.gitignore:2`), so the repository itself does not pin those versions.
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
| **F-3** | MED | PSI zero-padding produces false-positive matches on padding slots | **NOT-FIXED** | Client still pads with `push(0n)` — `arcium-psi/tests/src/client.ts:25`. Circuit still does a bare `client.hashes[i] == server.hashes[j]` with no count field or per-side sentinel — `arcium-psi/encrypted-ixs/src/lib.rs:59`. |
| **F-4** | MED | `submit_psi_query`: the server dataset is supplied and encrypted by the caller, no on-chain anchoring | **NOT-FIXED** | `arcium-psi/programs/arcium-psi/src/lib.rs:57` — `server_data: SharedEncryptedStruct<10>` is still an instruction argument; the only validation is a non-zero encryption key (`:66-69`). No account, PDA or commitment binds it. (Full impact is `NEEDS-HOME`; the code state is unambiguous.) |
| **F-5** | MED | Unpinned GitHub Actions and package installs in workflows holding `ANTHROPIC_API_KEY` | **PARTIAL** *(corrected 2026-09-29)* | **Gone:** every workflow that held `ANTHROPIC_API_KEY` — `karpathy-review.yml`, `pi-review.yml`, `security-review.yml` — was removed in commit `17682c5` (LLM reviews now run locally; `CLAUDE.md` «Ревью и CI» forbids LLM keys in workflows); no file under `.github/` references the key, `claude-code-action`, `claude-code-security-review` or `pi-coding-agent`. `graphify.yml` was removed earlier (PR #62). Least-privilege `permissions:` are set in `arcium-ci.yml:13-14` and `monthly-backup.yml:15-16`. **Remaining:** no workflow pins an action by commit SHA — every `uses:` is a tag (`actions/*@v4`, `actions/github-script@v7`, `reactivecircus/android-emulator-runner@v2`, `arcium-hq/setup-arcium@v0.10.4`); `monthly-backup.yml` still uses `actions/checkout@v3` (`:24`) and the archived `actions/create-release@v1` (`:39`) and `actions/upload-release-asset@v1` (`:55`); `arcium-ci.yml:32` runs `cargo install cargo-audit --locked` with no version. The original concern (a secret-holding workflow running unpinned code) no longer applies; the supply-chain pinning concern does. |
| **F-6** | MED | `hybrid_encaps` panics on a malformed peer public key (future FFI DoS) | **FIXED** | Commit `3dcd9c81` (PR #52). `crates/core-crypto/src/hybrid.rs:78` returns `Result<_, HybridError>`; the former `.expect()` calls on peer input are `.map_err(\|_\| HybridError)?` (`:85-90`). Tests `encaps_rejects_wrong_length_ml_kem_key`, `encaps_rejects_empty_ml_kem_key`, `encaps_rejects_right_length_but_invalid_ml_kem_key` pass. (The return type now carries a `Zeroizing<[u8; 64]>`, A-3.) |
| **F-7** | LOW | The hybrid KEM combiner does not bind ciphertexts and public keys into the KDF | **FIXED** (dormant) | PR #56 (merge `88243800`). `combine_secrets` (`hybrid.rs:158-188`) binds `eph_pk`, `ml_ct` and the recipient's X25519 and ML-KEM public keys; test `real_encaps_binds_recipient_identity_not_just_shared_secrets` passes. **Caveat:** `hybrid_encaps`/`hybrid_decaps` have no callers outside `core-crypto` (a search of `crates/` finds none) and are not exported through UniFFI, so the binding is correct at code level and has no effect until the module is wired into session establishment. |
| **F-8** | LOW | Transient secret copies are not zeroized | **PARTIAL** *(corrected 2026-09-29)* | **Fixed:** the transients of the 2026-07 sweep (identity blob in `load_identity`, `derive_root`'s `ikm`, hybrid seeds, `ArciumCore::new`'s master-key `Vec`; PR #54 and `d68ab02`) and, in A-3 (PR #103), the secrets that `core-crypto` owns in the ratchet, KDFs, X3DH, hybrid and checkpoint paths and the FFI temporaries in `mobile-ffi` — see A-3 for what is wiped and where. **Residual, outside this crate's control:** secret-derived state inside `hmac 0.12.1`, `hkdf 0.12.4` and `sha2 0.10.9` values is never wiped — none of them depends on `zeroize` or implements `Drop`; a keyed `Hmac` keeps `K ⊕ ipad` and `K ⊕ opad` compression states and its output block, `Hkdf` keeps a PRK-keyed HMAC core, and their stack locals are not wiped either (`hmac-0.12.1/src/optim.rs:152-173, 207-219`, `hkdf-0.12.4/src/lib.rs:150-170, 228-262`, `sha2-0.10.9/src/core_api.rs:60-68`). It cannot be erased without `unsafe` or a broader dependency change (`hmac`/`hkdf`/`sha2` 0.13/0.11 with their `zeroize` features add drop glue but still leave `K ⊕ opad` in a local); see H-9. Other transients still not wiped are H-1…H-6. |
| **F-9** | LOW | `load_identity` panics on a poisoned mutex; masks wrong-key decryption as "no identity" | **PARTIAL** | **Fixed:** a poisoned mutex returns `None` instead of panicking (`crates/mobile-ffi/src/lib.rs:595-598`), test `load_identity_returns_none_on_poisoned_mutex` (`:1099`). **Remaining:** the signature is still `-> Option<Arc<Identity>>` (`:592`) and any store error, wrong key included, is collapsed into `None` (`:599-602`). **Cross-ref (F-10):** since `core-storage` key names are master-key-derived hashes, a wrong master key fails the lookup itself and `get()` returns `NotFound`, so the "wrong key produces `Decryption`" path no longer arises for `load_identity` in practice; `Decryption` can still arise from corrupted data under a matching key. The gap — `Option` instead of a `Result` that distinguishes causes — is unchanged. |
| **F-10** | LOW | Storage: plaintext key names, size/pattern metadata leak, no rollback or secure-delete | **FIXED** *(scope stated 2026-09-29)* | PR #58 (merge `b2d3c5db`). **Covered:** (a) key names — `kv.k` is a `BLOB` of two HKDF-derived hashes and the name itself is stored encrypted in `ek` (`crates/core-storage/src/lib.rs:103-107`, `key_name_hash` `:286`, `storage_key` `:298`, `encrypt_key_name` `:320`); (b) `PRAGMA secure_delete = ON` (`:102`). Tests `key_names_are_not_stored_in_plaintext` (`:709`), `secure_delete_pragma_is_enabled` (`:775`), `deleted_row_bytes_are_overwritten_on_disk` (`:787`) pass. **Not covered, and not claimed:** row count and ciphertext length (no padding); rollback protection — an older copy of the database file is accepted (module doc `:15-21`; `docs/S2-B2-DURABLE-MESSAGING.md` §8, "malicious rollback … not provided"); `VACUUM`/`auto_vacuum`. The review itself called padding and rollback counters optional. FIXED here means the two sub-issues the review's fix named, not that the store is metadata-private against someone holding the file. |
| **F-11** | LOW | CI integrity: `arcium test` failure swallowed; dead `CLAUDE_SUCCESS`; Pi reviews a truncated diff | **FIXED** *(corrected 2026-09-29)* | `.github/workflows/arcium-ci.yml`: `arcium build` and its verification steps are plain commands that fail the job (`:53-54`, `:67-90`); the borsh tests run under `set -o pipefail` with a required-tests-ran check (`:81-90`); `arcium test` runs under `set -o pipefail` and `tee`, and fails on no passing test or any pending test (`:114-128`). The other two sub-items belonged to workflows that were deleted (`17682c5`, see F-5). The `\|\| true` that remain are diagnostics and gate nothing: tool versions (`:62-66`) and an `if: failure()` log dump (`:129-136`). CI evidence on `087b9c8`: Arcium CI run 36488538945, `arcium-build` and `arcium-test` `success`, `arcium-test` log `6 passing`. |
| **F-12** | LOW | Kotlin crypto stubs return plaintext as "ciphertext" | **FIXED** *(corrected 2026-09-29)* | `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt` no longer contains `ratchetEncrypt`, `ratchetDecrypt` or `x3dhInit` (a search of `android/app/src/main` finds none). Messaging methods forward to the generated UniFFI calls (`:63-250`); `submitPsiQuery` (`:257-263`) and `startTorTransport` (`:270-276`) throw `NotImplementedError` instead of returning a value that could be mistaken for a result. This is a static read; no Android tooling was used for this row (the Android CI jobs exercise the wrapper, but their results are not cited here). |
| **F-13** | INFO | X3DH: SPK signature lacks domain separation; OPK single-use unenforced | **FIXED** *(corrected 2026-09-29)* | (a) Domain separation: see F-2 (`x3dh.rs:17`, `:69-82`); a raw-key signature does not verify (test `signatures_from_other_contexts_are_rejected`). (b) One-time-prekey single use: `accept_first_message` (`mobile-ffi/src/lib.rs:849-927`) takes the one-time prekey (`:879`), rotates the prekey record (`:880-883`) and replaces it through a conditional `SideWrite::replace` (`:905-911`) in the same transaction that promotes the session; a lost race is `OneTimePrekeyUnavailable` (`:922`); `check_answerable` (`:824-838`) refuses a wrong id or a stripped one-time prekey. Tests `matching_one_time_prekey_is_consumed_and_replaced`, `replaying_an_accepted_handshake_is_rejected_and_changes_nothing`, `concurrent_first_messages_create_one_session_and_consume_the_prekey_once`, `stripping_the_one_time_prekey_is_refused_rather_than_downgraded`, `wrong_one_time_prekey_id_does_not_consume_the_current_one` pass. **Scope:** single use is enforced only where the responder holds a one-time prekey; a handshake answered without one has no replay property (`mobile-ffi/src/lib.rs:769-772`). |
| **F-14** | INFO | On-chain placeholders and result-delivery gap (pre-deploy) | **NOT-FIXED (pre-deploy)** · behavior `NEEDS-HOME` | `arcium-psi/programs/arcium-psi/src/lib.rs:7` — placeholder `declare_id!("PSiArc1um111…")`. The callback verifies the output signature (`:133-136`) but only `msg!`-logs the client's encryption key (`:141-144`); the match vector is written to no account or event. Legacy `submit_query` (`:21-32`) still ignores `encrypted_contacts` (`:30`). Access control on the implemented instructions read sound statically (payer-seeded `init_user` PDA `:153-158`, `has_one = owner` `:167`, monotonic nonce `:27`); MXE authority semantics are `NEEDS-HOME`. |
| **F-15** | INFO | Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir` | **NOT-FIXED (design)** · `NEEDS-HOME` *(scope clarified 2026-09-29)* | (a) `android/app/src/main/kotlin/com/arcium/messenger/network/SolanaClient.kt:7` uses `BuildConfig.SOLANA_RPC_URL` directly (clearnet). (b) `crates/core-transport/src/lib.rs:23-24` — `new(_state_dir)` ignores its argument and uses `TorClientConfig::default()`. **Scope:** the review wrote "messaging rides Tor (arti)"; that is not true of current code. `core-transport` is a `mobile-ffi` dependency in `Cargo.toml` but no source in `crates/` calls it, and `docs/NET-MESSAGING.md` records Tor as a stub and future work (`:25`) and states the relay path has "no anonymity and no Tor" (`:138-139`, `:231`). So F-15 covers the unwired Tor transport and the PSI/Solana RPC path only; the relay path's lack of anonymity is a documented design limit, not something this row tracks or claims to fix. |
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
| **A-3** | Secret key material outlived its use: `Copy` key types and by-value copies in the ratchet, KDF, X3DH, hybrid, checkpoint-decode and FFI paths. | **PARTIAL** (PR #103) | **Done:** the ratchet's secret fields and every key-derived temporary that `core-crypto` owns are `Zeroizing`/wiping types (`crates/core-crypto/src/ratchet.rs:50-52`; `impl ZeroizeOnDrop for DoubleRatchet` `:350`; no manual `Drop` on the ratchet); the rollback snapshot wipes through its fields; X3DH (`x3dh.rs:106, 151`), hybrid and checkpoint decode hold their secrets in `Zeroizing`; the FFI temporaries in `mobile-ffi` are wrapped (`mobile-ffi/src/lib.rs:336-337, 364-376, 570, 582, 600, 606-607`). Wire and checkpoint formats are unchanged. Tests: compile-time pins `secret_fields_are_wiping_types` (`ratchet.rs:832`), drop-time probes `secret_fields_wipe_on_drop` (`:862`) and `the_production_container_wipes_on_drop` (`:904`), `no_temporary_key_outlives_an_operation` (`:983`), `copies_and_restores_give_every_key_back` (`:1040`). **Not done — why it is PARTIAL:** secret-derived state inside third-party `hmac`/`hkdf`/`sha2` values (H-9) and the items H-1…H-8, H-10. Not established: the actual memory contents after drop on a device, and that the Android release `.so` keeps `zeroize`'s writes (H-8); the wipe tests show *where* containers are dropped, not that memory was cleared. |

---

## H-series: memory-hygiene follow-ups (recorded, not fixed)

Surfaced while reviewing A-3 and while reconciling this file. **Recorded only — this PR
changes no code**, and none of these is claimed fixed. Severity is the reviewer's estimate;
each needs a local attacker who can later read process memory (a core dump, swapped pages,
a memory-disclosure bug). Labels: `SV` SOURCE_VERIFIED, `INF` INFERRED, `NV` NOT_VERIFIED.

| ID | Sev | Item | Anchor (`main` @ `087b9c8`) | Label |
|----|-----|------|-----------------------------|-------|
| **H-1** | LOW | `core-storage` subkeys are plain `[u8; 32]` wiped by a manual `zeroize()` call that an early `?` or a panic skips: `decrypt_key_name` (`?` at `:344`, wipe at `:345`), `encrypt` (`?` at `:369`, wipe at `:374`), `decrypt` (`?` at `:393`, wipe at `:395`). `subkey` and `key_name_encryption_subkey` return plain arrays (`:310-315`, `:349-354`). The master key itself is wiped in `Drop` (`:400-403`). | `crates/core-storage/src/lib.rs` | SV |
| **H-2** | LOW | `RescueCipher` keeps its key in a plain `[u8; 32]` with no `Drop`, and `from_shared_secret` copies it from the caller's array. This is the M-3 stub (`CLAUDE.md`, «Постоянные ограничения»); the real cipher would need its own review, and this row does not authorize replacing it. | `crates/core-crypto/src/rescue.rs:21-27` | SV |
| **H-3** | LOW | `AliceSession` derives `Debug` and holds `root_key: Zeroizing<[u8; 32]>`; `Zeroizing` derives `Debug` and prints its contents (zeroize 1.9.0 `src/lib.rs:602`), so formatting an `AliceSession` with `{:?}` prints the root key. No call that formats it was found in `mobile-ffi` or `x3dh.rs` (latent, not exploited). `BobSession` has no `Debug`. | `crates/core-crypto/src/x3dh.rs:103-106` | SV |
| **H-4** | LOW | `ArciumCore::new` wraps the caller's `Vec` in `Zeroizing`, but copies the key into a plain local `[u8; 32]` (`try_into`) and passes that array by value to `EncryptedStore::open`; the local is not wiped. | `crates/mobile-ffi/src/lib.rs:570-574`, `crates/core-storage/src/lib.rs:65` | SV |
| **H-5** | LOW | `StagedTransition<T>` wipes the ratchet and the record when dropped without commit, but `output: T` is not wrapped: for a staged receive, `T` is the decrypted plaintext as a plain `Vec<u8>`, so the plaintext of an abandoned transition is not wiped. | `crates/core-protocol/src/durable.rs:522-529, 723` | SV |
| **H-6** | LOW | The skipped-key store is an `IndexMap` of `Zeroizing` keys; `swap_remove`, `shift_remove_index` and growth move entries bitwise, so stale copies can remain in spare capacity or in a freed buffer. | `crates/core-crypto/src/ratchet.rs:108, 233, 342` | INF (from `indexmap`'s design; not observed) |
| **H-7** | LOW | Moves of secret arrays and `StaticSecret::from(*bytes)` copy the secret onto the stack (`x25519` takes the array by value); the source array is then wiped, the stack copy is not. | `crates/core-crypto/src/ratchet/checkpoint.rs:324`, `crates/core-crypto/src/hybrid.rs:120`, `crates/mobile-ffi/src/lib.rs:377, 387, 610` | SV (copy sites); INF (that the stack copies persist) |
| **H-8** | INFO | Wipes run on drop and on unwinding only. `abort`, `SIGKILL`, `mem::forget`, swap and core dumps are outside them. Root `Cargo.toml:28-32` (`[profile.release]`) sets no `panic` key, so the default (unwind) applies. Not checked: that the Android release `.so` retains `zeroize`'s volatile writes, and the memory of a real device. | root `Cargo.toml:28-32` | SV (profile); **NV** (release-`.so` behaviour, device memory — would need disassembly and memory forensics) |
| **H-9** | LOW | Secret-derived state inside `hmac 0.12.1`, `hkdf 0.12.4` and `sha2 0.10.9` (keyed compression states, `K ⊕ opad` locals, HMAC/HKDF outputs) is never wiped: none of the crates implements `Drop` or uses `zeroize`. Our callers: `kdf_ck`/`kdf_rk` (`ratchet.rs:380-411`), `derive_root` (`x3dh.rs:187-210`), `combine_secrets` (`hybrid.rs:158-188`), storage subkeys. Cannot be removed without `unsafe` or a broader dependency change; the 0.13/0.11 lines with a `zeroize` feature add drop glue but keep `K ⊕ opad` in a local, and mean a major upgrade of the crypto stack (a separate, owner-scoped task). See F-8. | see F-8 row for third-party `path:line` | SV (sources of the versions CI resolved); the version citation rests on CI logs, see the evidence basis |
| **H-10** | LOW (supply chain) | `Cargo.lock` is git-ignored (`.gitignore:2`), so the repository does not pin the versions of `hmac`, `hkdf`, `sha2`, `zeroize` or anything else; each CI run resolves afresh, and `cargo audit` audits whatever was resolved then. Any statement about a third-party crate version in this file is about the versions named in the evidence basis, not about what the repository guarantees. | `.gitignore:2` | SV |

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
| **X-1** | Identity-persistence silent key-loss (the Kotlin-side consequence of F-9: a `None` on wrong-key/`NotFound` leads onboarding to generate and overwrite a real identity) | **MERGED** *(corrected 2026-09-29; was «FIXED / UNMERGED»)* | PR #48 merged (`98ad3a2`). `ArciumCore.kt:309` now has a real `openEncryptedDb`; `ArciumApp.kt:20` calls it with the master key from `security/MasterKeyProvider.kt`. Read statically; the startup flow was not exercised here (the emulator manual test the old row waited for is not evidenced in this snapshot), and the Rust-side gap of F-9 is unchanged. |
| **X-2** | `require_identity()` — a private helper — was exported to Kotlin as callable `requireIdentity(): Identity` because it sat inside a `#[uniffi::export] impl` block | **FIXED / MERGED** | PR #50 (merge `492c5d1`). `require_identity` is defined at `crates/mobile-ffi/src/lib.rs:971`, inside a plain `impl ArciumCore` (`:932`) separate from the exported block (`:563-564`). (The 2026-07-19 row cited `:389-390`; the code has moved.) |
| **X-3** | **Lesson (guidance, not a bug):** `#[uniffi::export]` applies to an entire `impl` block — every method in it is exported regardless of Rust `pub`/private visibility. Private helpers must live in a separate non-exported `impl` block. | **N/A (standing guidance)** | Root cause of X-2. Applies to any future `#[uniffi::export] impl` in `crates/mobile-ffi`. |

---

## Prioritized remaining work

Regenerated 2026-09-29 from the tables above; the 2026-07-19 list is superseded. Order is
the reviewer's suggestion, not a commitment, and every item needs its own task, its own PR
and an explicit owner instruction (crypto and protocol changes are never bundled).

1. **F-3** PSI padding convention — must precede the `CIRCUIT_HASH` freeze and a devnet
   deploy.
2. **F-4**, **F-14** server-set anchoring and the result-delivery gap — with the MXE deploy;
   behaviour is `NEEDS-HOME`.
3. **F-5** pin actions by commit SHA and give `cargo install cargo-audit` a version; retire
   the archived release actions in `monthly-backup.yml`. **H-10** (commit or otherwise pin
   `Cargo.lock`) belongs with it.
4. **F-9** give `load_identity` a `Result` so a wrong key is distinguishable from "no
   identity" (FFI boundary).
5. **H-1…H-7** the remaining memory-hygiene items, and **H-9** as a dependency decision
   (`hmac`/`hkdf`/`sha2` 0.13/0.11) once the owner chooses to take the crypto-stack upgrade.
6. **F-15** and **F-16** at devnet integration: the Tor transport is unwired, and the PSI
   client's nonce and low-order-point handling need a production caller's decision.
7. **H-8** verify release-build wiping on a device, when a device is available.

---

*This tracker is a documentation artifact only; it changes no code. Its statuses are a
snapshot at `main` @ `087b9c8` on 2026-09-29 — except **F-17**, whose closure record dates
from `main` @ `1a7b1904` (2026-07-28) with the re-check note above. Re-verify a row against
the source at your own target SHA before relying on it, and do not read a `FIXED` here as a
statement about anything the row does not name.*
