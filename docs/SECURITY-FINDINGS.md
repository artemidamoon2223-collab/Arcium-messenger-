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
| **F-2** | MED | X3DH: no binding between Ed25519 `signing_pk` and X25519 `identity_pk` | **NOT-FIXED** | `crates/core-crypto/src/x3dh.rs:37-38` still verifies the SPK sig against the `signing_pk` carried *inside the same bundle*; AD at `:60-61` is `our_identity_pk ‖ bob.identity_pk` — still excludes `signing_pk`. No cross-certification. |
| **F-3** | MED | PSI zero-padding produces false-positive matches on padding slots | **NOT-FIXED** | Client still pads with `push(0n)` — `arcium-psi/tests/src/client.ts:25`. Circuit still does bare `client.hashes[i] == server.hashes[j]` with no count field / per-side sentinel — `arcium-psi/encrypted-ixs/src/lib.rs:59`. |
| **F-4** | MED | `submit_psi_query`: server dataset supplied+encrypted by the caller, no on-chain anchoring | **NOT-FIXED** | `arcium-psi/programs/arcium-psi/src/lib.rs:55` — `server_data: SharedEncryptedStruct<10>` is still an instruction arg; only validation is non-zero keys (`:61-65`). No account/PDA/commitment binds it. (Full impact is `NEEDS-HOME`, but the code state is unambiguously unfixed.) |
| **F-5** | MED | Unpinned GitHub Actions + package installs in workflows holding `ANTHROPIC_API_KEY` | **PARTIAL** | **Fixed:** `pi-review.yml:27` pinned `@earendil-works/pi-coding-agent@0.80.3`; `security-review.yml:27` SHA-pinned `claude-code-security-review@0c6a49f…`; least-privilege `permissions:` added to `arcium-ci.yml` + `monthly-backup.yml` (`5d84087`), `allowBackup=false` (`1ae5f72`). **Remaining:** `anthropics/claude-code-action@beta` (`karpathy-review.yml:24`, `graphify.yml:29`); unversioned `pip install graphifyy` (`graphify.yml:21`); archived `actions/create-release@v1` + `actions/upload-release-asset@v1` and stale `actions/checkout@v3` (`monthly-backup.yml:24,39,55`). |
| **F-6** | MED | `hybrid_encaps` panics on malformed peer public key (future FFI DoS) | **FIXED** | commit `3dcd9c81` (PR #52). `crates/core-crypto/src/hybrid.rs`: `hybrid_encaps` now returns `Result<(Vec<u8>, [u8;64]), HybridError>`, with both former `.expect()` calls on peer-controlled input replaced by `.map_err(|_| HybridError)?` (mirroring `hybrid_decaps`, exactly as the review recommended). Tests `encaps_rejects_wrong_length_ml_kem_key`, `encaps_rejects_empty_ml_kem_key`, `encaps_rejects_right_length_but_invalid_ml_kem_key` — all **pass**, proving malformed peer input now returns `Err`, not a panic (verified 2026-07-19). |
| **F-7** | LOW | Hybrid KEM combiner doesn't bind ciphertexts/public keys into the KDF | **FIXED** | **PR #56** (merge commit `88243800`). `hybrid.rs`'s `combine_secrets` now binds `eph_pk`, `ml_ct`, and the recipient's `x25519`+`ml_kem` public keys into the HKDF input — previously only the two raw shared secrets. `hybrid_decaps` re-derives the same values symmetrically (its own X25519 pubkey from `sk.x25519`, its own ML-KEM encapsulation key via `dk.encapsulation_key()`). Test `real_encaps_binds_recipient_identity_not_just_shared_secrets` proves two recipients with identical raw shared secrets now derive different keys (verified 2026-07-19). **Caveat:** the hybrid KEM module has no callers outside its own tests — not wired into X3DH, not exported through UniFFI — so this binding is correct at the code level but **dormant**: it has no effect until hybrid KEM is actually wired into session establishment. |
| **F-8** | LOW | Transient secret copies not zeroized | **FIXED** | decrypted identity blob in `load_identity` — `Zeroizing` (`d68ab02`, `mobile-ffi/src/lib.rs:210`); the remaining four transients closed by **PR #54** (merge commit `8d196859`): `x3dh::derive_root`'s `ikm` → `Zeroizing<Vec<u8>>`; `hybrid_keygen`'s and `hybrid_decaps`'s `seed_bytes` → `Zeroizing<[u8; 64]>` (both occurrences); `ArciumCore::new`'s caller-supplied `master_key` wrapped in `Zeroizing` on entry, wiped on every exit path. No signature changes (verified 2026-07-19). |
| **F-9** | LOW | `load_identity` panics on poisoned mutex; masks wrong-key decryption as "no identity" | **PARTIAL** | **Fixed:** poisoned mutex → `None` instead of panic (`1ae5f72`, `mobile-ffi/src/lib.rs:205-208`), test `load_identity_returns_none_on_poisoned_mutex`. **Remaining:** signature is still `-> Option<Arc<Identity>>` (`:202`); wrong-key `Decryption` is still collapsed into `None` (`:211`), so it's indistinguishable from `NotFound`. |
| **F-10** | LOW | Storage: plaintext key names, size/pattern metadata leak, no rollback/secure-delete | **NOT-FIXED** | `crates/core-storage/src/lib.rs:41,52` — `k TEXT PRIMARY KEY` (plaintext key names). No `PRAGMA secure_delete`, no key-name hashing/MAC, no padding. (Value crypto itself is sound — see review §3.) |
| **F-11** | LOW | CI integrity: `arcium test` failure swallowed; dead `CLAUDE_SUCCESS`; Pi reviews truncated diff | **NOT-FIXED** | `arcium-ci.yml:99` — `arcium test \|\| echo "…"` (never goes red). `karpathy-review.yml:58` — dead `${CLAUDE_SUCCESS:-}` branch (harmless; the `steps.claude_run.outcome` check is what actually gates). `pi-review.yml:54` — `git diff … \| head -500` still truncates. |
| **F-12** | LOW | Kotlin crypto stubs return plaintext as "ciphertext" | **NOT-FIXED** — *planned: Stage 4.3* | `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt:33` `return plaintext`, `:38` `return ciphertext` (echo); `:28` `x3dhInit` still returns `ByteArray(32)`. (`generateIdentity` at `:23` *is* now real via PR #46.) **Forward-link:** Stage 4.3 (Kotlin messaging wiring — designed, no PR yet) will close this by replacing `ratchetEncrypt`/`ratchetDecrypt`'s echo behavior with real calls into the already-merged `encryptMessage`/`decryptMessage` FFI methods (PR #49), and retiring `x3dhInit` in favor of `establishSessionInitiator`/`establishSessionResponder` (also PR #49). Forward-reference only — status stays NOT-FIXED until 4.3 actually lands. |
| **F-13** | INFO | X3DH: SPK signature lacks domain separation; OPK single-use unenforced | **NOT-FIXED** | `x3dh.rs:38` signs the raw 32-byte SPK with no context label (no `"X3DH-SPK-v1"` prefix). No layer tracks/deletes used one-time prekeys anywhere in the repo. |
| **F-14** | INFO | On-chain placeholders + result-delivery gap (pre-deploy) | **NOT-FIXED (pre-deploy)** · behavior `NEEDS-HOME` | `arcium-psi/programs/arcium-psi/src/lib.rs:5` — placeholder `declare_id!("PSiArc1um111…")`. Callback still `msg!`-logs the client key without writing the match vector to an account/event. Access-control review (`init_user` PDA, `has_one = owner`, monotonic nonce) confirmed sound statically; MXE authority is `NEEDS-HOME`. |
| **F-15** | INFO | Solana RPC path bypasses Tor by design; `core-transport` ignores `state_dir` | **NOT-FIXED (design)** · `NEEDS-HOME` | `android/.../network/SolanaClient.kt:7` uses `BuildConfig.SOLANA_RPC_URL` directly (clearnet). `crates/core-transport/src/lib.rs:23-24` — `new(_state_dir)` ignores the arg and uses `TorClientConfig::default()`. Design decision, deferred to FFI wiring. |
| **F-16** | INFO | TS client: raw ECDH output used directly as `RescueCipher` key | **CANNOT-VERIFY-FROM-CODE** · `NEEDS-HOME` | `arcium-psi/tests/src/client.ts:16` returns raw `x25519.getSharedSecret`; `:28` `new RescueCipher(sharedSecret)` with no explicit KDF. Whether this is safe depends on `@arcium-hq/client`'s internal derivation — not determinable from repo source. Code unchanged since review. |
| **F-17** | INFO | Docs drift in `CLAUDE.md` | **NOT-FIXED** | 10 workflow files on disk vs 5 rows in the `CLAUDE.md` workflow table; `pi-review.yml`, `graphify.yml`, `AppNavigation.kt`, `SolanaClient.kt`, `BluetoothMeshManager.kt`, `docs/` still not reflected in the repo-structure map. |

---

## Non-F-series items (surfaced during recent work)

These aren't in the 2026-06 F-series but were found during subsequent development and
should be tracked alongside it.

| ID | Description | Status | Evidence |
|----|-------------|--------|----------|
| **X-1** | Identity-persistence silent key-loss (the Kotlin-side consequence of F-9: a `None` on wrong-key/`NotFound` leads onboarding to generate + overwrite a real identity) | **FIXED / UNMERGED** | Fix lives in open **PR #48** (`feat/android-identity-persistence`): real `MasterKeyProvider` + `openEncryptedDb`/`generateAndSaveIdentity` + startup skip-onboarding check. On `main` it is still a stub — `ArciumCore.kt:50-51` `openEncryptedDb` is a `// TODO` no-op. Not yet merged (awaiting manual emulator test). |
| **X-2** | `require_identity()` — a private helper — was exported to Kotlin as callable `requireIdentity(): Identity` purely because it sat inside a `#[uniffi::export] impl` block | **FIXED / MERGED** | **PR #50** (merge commit `492c5d1`). `crates/mobile-ffi/src/lib.rs:389-390` — `require_identity` now lives in a separate plain `impl ArciumCore` block; fresh UniFFI bindgen confirms `requireIdentity` absent from generated Kotlin while all six messaging methods remain. |
| **X-3** | **Lesson (guidance, not a bug):** `#[uniffi::export]` applies to an entire `impl` block — every method in it is exported regardless of Rust `pub`/private visibility. Private helpers must live in a separate non-exported `impl` block. | **N/A (standing guidance)** | Root cause of X-2. Applies to any future `#[uniffi::export] impl` in `crates/mobile-ffi`. |

---

## Prioritized remaining work (from the review's §6, minus what's since fixed)

F-1, F-6, F-7, and F-8 are done. The next code-affecting items the review flagged as
pre-freeze / pre-deploy:

1. **F-3** PSI padding convention — must precede `CIRCUIT_HASH` freeze + devnet deploy.
2. **F-2 (+F-13)** X3DH identity/signing-key binding + domain-separated SPK signature —
   must precede bundle-server format freeze.
3. **F-5** finish pinning the remaining third-party actions/installs (mechanical).
4. **F-9** give `load_identity` a `Result` so wrong-key is distinguishable from "no
   identity" — sits on the FFI boundary. (**F-6**, previously grouped here, is now
   FIXED — see the table above.)
5. Then: **F-10** storage metadata, **F-4** server-set anchoring (with MXE deploy),
   **F-11/F-12** CI + stub fail-closed, **F-14/F-15/F-16** at devnet integration.
   (**F-8**, previously listed here, is now FIXED — see the table above.)

---

*This tracker is a documentation artifact only. It changes no code. Statuses are a
point-in-time snapshot at `main` @ `492c5d1f` on 2026-07-19 and should be re-verified
against source whenever a finding is claimed fixed.*
