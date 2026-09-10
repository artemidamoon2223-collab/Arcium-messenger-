# Security Findings Tracker — Arcium Messenger

**Reconstructed from code inspection on `main` @ `492c5d1f6385ddf698cf210ec29f0d67fb6a1d8f`, 2026-07-19.**

## How this tracker was built

The statuses below were derived by **reading the current source on `main`**, not from
memory. Every `FIXED` / `NOT-FIXED` / `PARTIAL` claim is backed by a commit SHA, a
`file:line`, or a passing test name. A finding whose original definition cannot be
recovered from anywhere in the repo is flagged as such rather than guessed.

### Where the finding definitions come from

- Full original definitions for every finding live in
  [`docs/SECURITY-REVIEW-2026-06-deep.md`](./SECURITY-REVIEW-2026-06-deep.md) — the
  2026-06-09 deep review, imported into `main` verbatim (with a header noting this
  tracker supersedes its status language). Until this PR, that document **did not exist
  on `main`** — it lived only on the unmerged remote branch
  `origin/claude/arcium-security-deep-review-inlyr2` (commit `d46f6eb`, 427 lines).
  Recovering and importing it here is what makes this tracker self-contained: the
  definitions no longer depend on a branch that could disappear.
- The task referred to findings **F-1 … F-13**. The review actually defines **17
  findings, F-1 … F-17** (1 HIGH, 5 MED, 6 LOW, 5 INFO). All 17 have a recoverable
  in-repo definition, verified present in the imported copy; none had to be invented.
  F-14…F-17 are tracked here too.
- Before this PR, the only `F-nn` references anywhere in tracked source on `main` were
  **F-1** comments (regression-test docs in `crates/core-crypto/src/ratchet.rs:517,574`
  and `crates/mobile-ffi/src/lib.rs:362,591`). No other finding number was referenced in
  main's source — their statuses lived only in scattered conversation until now.
- **This file is the authoritative *current* status for every finding.** The imported
  review is preserved as a historical snapshot for context/definitions only — its own
  status language reflects 2026-06-09, not today.
- **F-13 is tracked as two rows, F-13-A and F-13-B.** The review's F-13 bundles two
  independent defects — SPK signature domain separation, and one-time-prekey single
  use — that live in different files and could have been fixed separately. One row
  could not carry two statuses honestly. The split also restores a consequence the
  original single row had dropped when it was condensed from the review: the review
  states outright that with no OPK enforcement "replay of Alice's first message
  re-derives the same session" (`SECURITY-REVIEW-2026-06-deep.md:329-333`); the
  2026-07-19 row said only "OPK single-use unenforced". That loss was itself the class
  of drift F-17 is about, and is recorded here so it is not repeated.

### Status vocabulary

- **FIXED** — vulnerable code is gone on `main`; evidence = commit + file:line and/or test.
- **PARTIAL** — part of the finding is fixed, part remains; both sides cited.
- **NOT-FIXED** — the vulnerable code quoted in the review is still present on `main`.
- **NEEDS-HOME / CANNOT-VERIFY-FROM-CODE** — status can't be settled by reading source
  (requires devnet, a device, open network, or third-party library internals). Current
  code state is reported; behavioral confirmation is deferred.

---

## F-series findings (from the 2026-06 deep review)

| ID | Sev | One-line (from recovered review) | Status | Evidence (on `main` @ 492c5d1f unless noted) |
|----|-----|----------------------------------|--------|----------------------------------------------|
| **F-1** | HIGH | Ratchet state mutated before AEAD auth → unauthenticated attacker permanently desyncs a session | **FIXED** | commit `1ae5f72`. `ratchet.rs`: `decrypt` snapshots then rolls back on any error (`:160-168`), `RatchetSnapshot` with zeroizing `Drop` (`:333`). Tests `forged_unknown_dh_message_does_not_mutate_state`, `forged_ciphertext_reusing_skipped_key_header_does_not_consume_key` — both **pass** (verified 2026-07-19). |
| **F-2** | MED | X3DH: no binding between Ed25519 `signing_pk` and X25519 `identity_pk` | **FIXED** | **PR #81** (merge commit `99c9f492`, commits `c7c973d` + `9127ad0`), re-verified at `main` @ `99c9f492` on 2026-09-10. The signed-prekey signature now covers `SIGNED_PREKEY_OBJECT_V1` — `crates/core-crypto/src/x3dh.rs:69-82`, 116 bytes (`:20`): domain ‖ version ‖ suite ‖ `identity_dh_pk` ‖ `signing_pk` ‖ `signed_prekey_pk`. This is the cross-certification route the review recommended: the Ed25519 key now signs the X25519 identity, so pairing a victim's `signing_pk` with an attacker's `identity_pk` no longer verifies (the reverse pairing never gained anything — `dh2` still needs the identity secret). Test `substituted_identity_dh_key_is_rejected` (`x3dh.rs:278`) proves the swap fails; `bundle_with_substituted_identity_key_is_rejected` (`crates/mobile-ffi/src/lib.rs:1581`) proves it at the FFI boundary with two real peers' bundles. 125 host tests pass; six-test instrumentation suite reported `OK (6 tests)` by the owner on a Pixel 10a (arm64-v8a) against the PR #81 build — that run exercises the honest path, not the rejection. **Scope limit, stated so this row is not over-read:** FIXED closes the defect as the review defines it — the *internal* binding between the two keys in one bundle. The review's exploit scenario also names a malicious key server replacing the *whole* bundle with a self-consistent one of its own; internal binding cannot stop that, only out-of-band provenance can (fingerprint verification, a directory), and no such convention exists in the repo yet. That is a separate problem — contact-to-bundle authentication — not covered by this row. |
| **F-3** | MED | PSI zero-padding produces false-positive matches on padding slots | **NOT-FIXED** | Client still pads with `push(0n)` — `arcium-psi/tests/src/client.ts:25`. Circuit still does bare `client.hashes[i] == server.hashes[j]` with no count field / per-side sentinel — `arcium-psi/encrypted-ixs/src/lib.rs:59`. |
| **F-4** | MED | `submit_psi_query`: server dataset supplied+encrypted by the caller, no on-chain anchoring | **NOT-FIXED** | `arcium-psi/programs/arcium-psi/src/lib.rs:55` — `server_data: SharedEncryptedStruct<10>` is still an instruction arg; only validation is non-zero keys (`:61-65`). No account/PDA/commitment binds it. (Full impact is `NEEDS-HOME`, but the code state is unambiguously unfixed.) |
| **F-5** | MED | Unpinned GitHub Actions + package installs in workflows holding `ANTHROPIC_API_KEY` | **PARTIAL** | **Fixed:** `pi-review.yml:27` pinned `@earendil-works/pi-coding-agent@0.80.3`; `security-review.yml:27` SHA-pinned `claude-code-security-review@0c6a49f…`; least-privilege `permissions:` added to `arcium-ci.yml` + `monthly-backup.yml` (`5d84087`), `allowBackup=false` (`1ae5f72`); unversioned `pip install graphifyy` (`graphify.yml:21`) closed by deletion of `graphify.yml` in PR #62 — removal, not version-pinning. **Remaining:** `anthropics/claude-code-action@beta` (`karpathy-review.yml:24`); archived `actions/create-release@v1` + `actions/upload-release-asset@v1` and stale `actions/checkout@v3` (`monthly-backup.yml:24,39,55`). |
| **F-6** | MED | `hybrid_encaps` panics on malformed peer public key (future FFI DoS) | **FIXED** | commit `3dcd9c81` (PR #52). `crates/core-crypto/src/hybrid.rs`: `hybrid_encaps` now returns `Result<(Vec<u8>, [u8;64]), HybridError>`, with both former `.expect()` calls on peer-controlled input replaced by `.map_err(|_| HybridError)?` (mirroring `hybrid_decaps`, exactly as the review recommended). Tests `encaps_rejects_wrong_length_ml_kem_key`, `encaps_rejects_empty_ml_kem_key`, `encaps_rejects_right_length_but_invalid_ml_kem_key` — all **pass**, proving malformed peer input now returns `Err`, not a panic (verified 2026-07-19). |
| **F-7** | LOW | Hybrid KEM combiner doesn't bind ciphertexts/public keys into the KDF | **FIXED** | **PR #56** (merge commit `88243800`). `hybrid.rs`'s `combine_secrets` now binds `eph_pk`, `ml_ct`, and the recipient's `x25519`+`ml_kem` public keys into the HKDF input — previously only the two raw shared secrets. `hybrid_decaps` re-derives the same values symmetrically (its own X25519 pubkey from `sk.x25519`, its own ML-KEM encapsulation key via `dk.encapsulation_key()`). Test `real_encaps_binds_recipient_identity_not_just_shared_secrets` proves two recipients with identical raw shared secrets now derive different keys (verified 2026-07-19). **Caveat:** the hybrid KEM module has no callers outside its own tests — not wired into X3DH, not exported through UniFFI — so this binding is correct at the code level but **dormant**: it has no effect until hybrid KEM is actually wired into session establishment. |
| **F-8** | LOW | Transient secret copies not zeroized | **FIXED** | decrypted identity blob in `load_identity` — `Zeroizing` (`d68ab02`, `mobile-ffi/src/lib.rs:210`); the remaining four transients closed by **PR #54** (merge commit `8d196859`): `x3dh::derive_root`'s `ikm` → `Zeroizing<Vec<u8>>`; `hybrid_keygen`'s and `hybrid_decaps`'s `seed_bytes` → `Zeroizing<[u8; 64]>` (both occurrences); `ArciumCore::new`'s caller-supplied `master_key` wrapped in `Zeroizing` on entry, wiped on every exit path. No signature changes (verified 2026-07-19). |
| **F-9** | LOW | `load_identity` panics on poisoned mutex; masks wrong-key decryption as "no identity" | **PARTIAL** | **Fixed:** poisoned mutex → `None` instead of panic (`1ae5f72`, `mobile-ffi/src/lib.rs:205-208`), test `load_identity_returns_none_on_poisoned_mutex`. **Remaining:** signature is still `-> Option<Arc<Identity>>` (`:202`); wrong-key `Decryption` is still collapsed into `None` (`:211`), so it's indistinguishable from `NotFound`. **Cross-ref (F-10/PR #58):** since `core-storage`'s key names are now master-key-derived hashes, a wrong master key now fails the *lookup itself* — `get()` returns `NotFound` directly, not `Decryption` — so this specific "wrong-key produces `Decryption`" path no longer occurs for `load_identity` in practice (`Decryption` can still arise from corrupted value data under a *correctly*-matching key). The underlying gap this row is about — `load_identity` returning `Option` instead of a `Result` that could distinguish causes — is otherwise unchanged; status stays PARTIAL. |
| **F-10** | LOW | Storage: plaintext key names, size/pattern metadata leak, no rollback/secure-delete | **FIXED** | **PR #58** (merge commit `b2d3c5db`). Both sub-issues closed: **(a)** key names — `kv.k` is now `BLOB PRIMARY KEY` = `namespace_hash(32) ‖ full_key_hash(32)` via `HKDF-SHA256(master_key, ...)`, replacing the plaintext `TEXT PRIMARY KEY`; a new `ek` column holds each key name encrypted under a dedicated subkey so `list_keys_with_prefix` still returns real key names after an exact-namespace-hash match. **(b)** `secure_delete` — `PRAGMA secure_delete = ON` added to both `open()`/`open_in_memory()`. 6 new tests, including one that captures the actual stored ciphertext bytes and confirms they don't survive anywhere in the raw file after `delete()` (verified 2026-07-19). Padding, rollback counters, and `auto_vacuum` remain out of scope — the review itself framed them as optional/deferred. |
| **F-11** | LOW | CI integrity: `arcium test` failure swallowed; dead `CLAUDE_SUCCESS`; Pi reviews truncated diff | **NOT-FIXED** | `arcium-ci.yml:99` — `arcium test \|\| echo "…"` (never goes red). `karpathy-review.yml:58` — dead `${CLAUDE_SUCCESS:-}` branch (harmless; the `steps.claude_run.outcome` check is what actually gates). `pi-review.yml:54` — `git diff … \| head -500` still truncates. |
| **F-12** | LOW | Kotlin crypto stubs return plaintext as "ciphertext" | **NOT-FIXED** — *planned: Stage 4.3* | `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt:33` `return plaintext`, `:38` `return ciphertext` (echo); `:28` `x3dhInit` still returns `ByteArray(32)`. (`generateIdentity` at `:23` *is* now real via PR #46.) **Forward-link:** Stage 4.3 (Kotlin messaging wiring — designed, no PR yet) will close this by replacing `ratchetEncrypt`/`ratchetDecrypt`'s echo behavior with real calls into the already-merged `encryptMessage`/`decryptMessage` FFI methods (PR #49), and retiring `x3dhInit` in favor of `establishSessionInitiator`/`establishSessionResponder` (also PR #49). Forward-reference only — status stays NOT-FIXED until 4.3 actually lands. |
| **F-13-A** | INFO | X3DH: SPK signature lacks domain separation (first half of the review's F-13) | **FIXED** | **PR #81** (`99c9f492`), re-verified at `main` @ `99c9f492` on 2026-09-10. The signature input is now the domain-separated `SIGNED_PREKEY_OBJECT_V1` — domain `"arcium/x3dh-spk/v1"` (`crates/core-crypto/src/x3dh.rs:17`) followed by protocol version and cipher suite (`:76-77`), so the same Ed25519 key signing a bare 32-byte value elsewhere can no longer be confused with a prekey endorsement, and a bundle cannot be re-presented under a different version or suite with its old signature. Verification also moved from `verify` to `verify_strict` (`x3dh.rs:99`; repo-wide grep for `.verify(` finds nothing): the signing key travels inside the untrusted bundle it authenticates, and the strict form rejects small-order keys, the case where one signature can validate under more than one key. Tests: `signatures_from_other_contexts_are_rejected` (legacy raw-key signature, foreign domain, other suite — all refused) and `small_order_signing_key_is_rejected_by_strict_verification` (`x3dh.rs:375`). |
| **F-13-B** | INFO | X3DH: one-time-prekey single use unenforced — and, as the review states, replay of the first message therefore re-derives the same session (second half of F-13; the replay consequence was dropped from the 2026-07-19 row and is restored here from `SECURITY-REVIEW-2026-06-deep.md:329-333`) | **FIXED** (for every reachable state — see X-5 for the residual) | **PR #81** (`99c9f492`), re-verified at `main` @ `99c9f492` on 2026-09-10. The bundle carries an opaque random `opk_id` beside the one-time prekey (`PREKEY_BUNDLE_V1`, 204 bytes, `crates/mobile-ffi/src/lib.rs:200`), the handshake echoes which one it used (`INITIATOR_HANDSHAKE_V1`, 84 bytes, `:213`), and the responder consumes that entry and publishes a replacement in the same transition (`:721-722`). A replayed handshake therefore names an identifier that is no longer current and is refused as `OneTimePrekeyUnavailable` before any state changes — test `replaying_an_accepted_handshake_is_rejected_and_changes_nothing` (`:1634`), which also asserts the persisted record is byte-identical after the refusal. A handshake that omits the OPK while one is published is refused as `OneTimePrekeyRequired` (`:728`) rather than downgraded — test `stripping_the_one_time_prekey_is_refused_rather_than_downgraded` (`:1691`); a bundle predating a rotation is refused as `StaleSignedPrekey` (`:714`) via the 8-byte `spk_id` (`crates/core-crypto/src/spk_id.rs:57`) — test `stale_signed_prekey_is_rejected` (`:1719`). **Exact property claimed, no wider:** replay is refused on every state reachable through `establish_prekeys` and the responder, because both always leave a one-time prekey published. The format also supports an SPK-only handshake with no OPK; that branch has no replay protection and no normal writer can produce the state that enables it. That residual is tracked as **X-5**, not closed here. Cutover is strict: storage key `prekeys/v1` → `prekeys/v2` (`:174`), legacy 161/193-byte bundles and 64-byte handshakes are rejected. |
| **F-14** | INFO | On-chain placeholders + result-delivery gap (pre-deploy) | **NOT-FIXED (pre-deploy)** · behavior `NEEDS-HOME` | `arcium-psi/programs/arcium-psi/src/lib.rs:5` — placeholder `declare_id!("PSiArc1um111…")`. Callback still `msg!`-logs the client key without writing the match vector to an account/event. Access-control review (`init_user` PDA, `has_one = owner`, monotonic nonce) confirmed sound statically; MXE authority is `NEEDS-HOME`. |
| **F-15** | INFO | Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir` | **NOT-FIXED (design)** · `NEEDS-HOME` | `android/.../network/SolanaClient.kt:7` uses `BuildConfig.SOLANA_RPC_URL` directly (clearnet). `crates/core-transport/src/lib.rs:23-24` — `new(_state_dir)` ignores the arg and uses `TorClientConfig::default()`. Design decision, deferred to FFI wiring. |
| **F-16** | INFO | TS client: raw ECDH output used directly as `RescueCipher` key | **CANNOT-VERIFY-FROM-CODE** · `NEEDS-HOME` | `arcium-psi/tests/src/client.ts:16` returns raw `x25519.getSharedSecret`; `:28` `new RescueCipher(sharedSecret)` with no explicit KDF. Whether this is safe depends on `@arcium-hq/client`'s internal derivation — not determinable from repo source. Code unchanged since review. |
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

---

## Non-F-series items (surfaced during recent work)

These aren't in the 2026-06 F-series but were found during subsequent development and
should be tracked alongside it.

| ID | Description | Status | Evidence |
|----|-------------|--------|----------|
| **X-1** | Identity-persistence silent key-loss (the Kotlin-side consequence of F-9: a `None` on wrong-key/`NotFound` leads onboarding to generate + overwrite a real identity) | **FIXED / UNMERGED** | Fix lives in open **PR #48** (`feat/android-identity-persistence`): real `MasterKeyProvider` + `openEncryptedDb`/`generateAndSaveIdentity` + startup skip-onboarding check. On `main` it is still a stub — `ArciumCore.kt:50-51` `openEncryptedDb` is a `// TODO` no-op. Not yet merged (awaiting manual emulator test). |
| **X-2** | `require_identity()` — a private helper — was exported to Kotlin as callable `requireIdentity(): Identity` purely because it sat inside a `#[uniffi::export] impl` block | **FIXED / MERGED** | **PR #50** (merge commit `492c5d1`). `crates/mobile-ffi/src/lib.rs:389-390` — `require_identity` now lives in a separate plain `impl ArciumCore` block; fresh UniFFI bindgen confirms `requireIdentity` absent from generated Kotlin while all six messaging methods remain. |
| **X-3** | **Lesson (guidance, not a bug):** `#[uniffi::export]` applies to an entire `impl` block — every method in it is exported regardless of Rust `pub`/private visibility. Private helpers must live in a separate non-exported `impl` block. | **N/A (standing guidance)** | Root cause of X-2. Applies to any future `#[uniffi::export] impl` in `crates/mobile-ffi`. |
| **X-4** | Responder read its prekey record under a store guard that was a temporary in an expression chain — `self.store.lock()?.get(…)?` — so the guard died at the end of the statement and X3DH ran unlocked. Harmless while nothing was ever written back, but any single-use scheme built on that shape would let two concurrent handshakes both consume the same one-time prekey. Found in the read-only audit that preceded PR #81. | **FIXED** | **PR #81** (`99c9f492`). The responder now holds one named `MutexGuard<EncryptedStore>` across read → validate → rotate → write (`crates/mobile-ffi/src/lib.rs:707-736`), performs exactly one `EncryptedStore::put` on the accepted path (`:722`), and releases the store guard before taking the session lock — the two are never held together. Crash atomicity rests on that single `put` being one SQLite statement in autocommit, not on the mutex, which only serializes threads. Test `concurrent_receipt_of_one_handshake_consumes_the_prekey_once` (`:1809`) releases two receivers through a `Barrier` and asserts exactly one acceptance and one durable advance; 40 consecutive runs pass, which raises the odds of real contention without guaranteeing it. **Lesson, same class as X-3:** a `lock()` inside a method chain is not a critical section. Bind the guard to a `let` when anything after the read depends on the value staying unchanged. |
| **X-5** | Residual replay on the SPK-only path. `ARCIUM_X3DH_FORMAT_V1` deliberately keeps a handshake form with no one-time prekey (`used_otp = 0`), and the responder accepts it when it holds no OPK. On that path nothing prevents an exact replay: the root key re-derives identically and a recorded first message decrypts. This is the residue of F-13-B, split out so F-13-B could be closed for what it actually closes. | **OPEN — currently unreachable** | On `main` @ `99c9f492` no production writer produces a record without a one-time prekey: `establish_prekeys` always publishes one and the responder always publishes a replacement, so `opk_present = false` is reachable only by constructing the record directly (which one test does, to keep the branch from rotting). The residual becomes live the moment a producer for that state appears — a bundle server with an exhaustion policy, or a deliberate publish-without-OPK mode — and must be closed in the same change that introduces it, not after. The owner's decision (Batch I/J, 2026-09) was: no dedup cache in the format PR, residual tracked explicitly here. Candidate closure when needed: a bounded persistent handshake-dedup structure written under the same store guard; it does not change wire bytes. |

---

## Prioritized remaining work (from the review's §6, minus what's since fixed)

F-1, F-2, F-6, F-7, F-8, F-10, F-13-A and F-13-B are done. The next code-affecting items
the review flagged as pre-freeze / pre-deploy:

1. **F-3** PSI padding convention — must precede `CIRCUIT_HASH` freeze + devnet deploy.
2. **F-5** finish pinning the remaining third-party actions/installs (mechanical).
3. **F-9** give `load_identity` a `Result` so wrong-key is distinguishable from "no
   identity" — sits on the FFI boundary. (**F-6**, previously grouped here, is now
   FIXED — see the table above.)
4. Then: **F-4** server-set anchoring (with MXE deploy), **F-11/F-12** CI + stub
   fail-closed, **F-14/F-15/F-16** at devnet integration. (**F-2/F-13**, previously
   item 2 here, landed as the protocol-format-v1 freeze in PR #81; the bundle-server
   format is now frozen at `ARCIUM_X3DH_FORMAT_V1`, and **X-5** must be closed together
   with whatever first makes the SPK-only state reachable.)

---

*This tracker is a documentation artifact only. It changes no code. Statuses are a
point-in-time snapshot at `main` @ `492c5d1f` on 2026-07-19 — except **F-17**, re-verified
at `main` @ `1a7b1904` on 2026-07-28, and **F-2, F-13-A, F-13-B, X-4, X-5**, verified at
`main` @ `99c9f492` on 2026-09-10 — and should be re-verified against source whenever a
finding is claimed fixed.*
