# Pre-Release / NO-GO Checklist — Arcium Messenger

Derived from `docs/SECURITY-REVIEW-2026-06-deep.md` (deep review, 2026-06).
This is a **tracking document, not a sign-off** — nothing here is marked "done".
Items are ordered by **dependency**, not by calendar. No deadlines.

Labels: **VERIFIED** = confirmed by static read · **NEEDS-HOME** = requires
devnet / device / open network to confirm behaviorally.

---

## MUST-FIX-BEFORE-MESSAGING
*Blocks any real end-to-end encrypted exchange. Do not ship messaging until closed.*

- [ ] **F-1** — `ratchet.rs::decrypt` commits DH-ratchet / chain state **before** AEAD
  authentication; one forged packet from an unauthenticated attacker permanently
  desyncs the session (remote DoS). Fix: transactional decrypt (commit state only
  after `aead_decrypt` succeeds) **+ regression test** (garbage header+ct must not
  break a subsequent legit message). · **VERIFIED**
  > Crypto-sensitive: a careless reorder can silently break forward secrecy or
  > out-of-order handling without failing existing tests. One PR, human diff review.

---

## MUST-FIX-BEFORE-MAINNET
*Blocks production with real users / on-chain. Several must precede a format or
circuit-hash freeze — noted inline.*

- [ ] **F-3** — PSI zero-padding (`0n`) on both sides yields false-positive matches on
  padding slots. Fix with per-side random sentinels or an explicit `count` field +
  circuit masking. **Must precede CIRCUIT_HASH freeze / devnet deploy** — changes the
  circuit or the client convention. · **VERIFIED** (logic) / **NEEDS-HOME** (e2e)
- [ ] **F-2 (+F-13)** — X3DH has no binding between Ed25519 `signing_pk` and X25519
  `identity_pk`; SPK signature gives no authentication against a malicious key server.
  Add key cross-certification (or XEdDSA identity), include `signing_pk` in AD and in
  the out-of-band fingerprint definition, and domain-separate the SPK signature.
  **Must precede bundle-server format freeze.** · **VERIFIED**
- [ ] **F-4** — `submit_psi_query` accepts the "server" dataset from the same caller as
  the client dataset; no on-chain anchoring of the server set, so the result proves
  nothing. Source `server_data` from a server-authority PDA / stored commitment.
  **Decide before devnet deploy.** · **VERIFIED**
- [ ] **F-5** — Supply chain: GitHub Actions pinned to mutable `@main`/`@beta`/`@vN`
  and unpinned npm/pip installs run in jobs holding `ANTHROPIC_API_KEY`. SHA-pin all
  third-party actions; version-pin installs; replace archived release actions.
  **See "F-5 pin manifest" below — blocked in-sandbox (no network to resolve SHAs).**
  · **VERIFIED**
- [ ] **F-6** — `hybrid_encaps` panics (`expect`) on a malformed peer ML-KEM key →
  remote-triggerable crash once exposed via FFI. Return `Result<_, HybridError>` like
  `hybrid_decaps` already does. · **VERIFIED**
- [ ] **F-9** — `load_identity` panics on a poisoned mutex (`.unwrap()`) and collapses
  wrong-key `Decryption` into `None`, so the app can silently regenerate an identity
  over the real one. Return `Result<Option<…>, CoreError>` and handle the mutex like
  `save_identity`. · **VERIFIED**

---

## REQUIRES-PROFESSIONAL-AUDIT
*Only a human crypto / protocol audit can close these. Static read is insufficient.*

- [ ] **F-7** — Hybrid KEM combiner does not bind ML-KEM ciphertext / public keys into
  the KDF (X-Wing / draft-ietf-tls-hybrid-design pattern). Confirm the construction at
  audit before the wire format freezes. · **VERIFIED** (design-level)
- [ ] **F-8** — Transient secret copies (handshake `ikm`, ratchet `mk`/chain stack
  copies, ML-KEM seed copies, decrypted identity blob, caller `master_key` Vec) are not
  zeroized. Needs empirical memory-forensics validation, not just a code sweep. ·
  **VERIFIED** (static) / **NEEDS-HOME** (forensics)
- [ ] **F-13** — SPK signature lacks domain separation; OPK single-use is not enforced
  at any layer (replay re-derives the same session). Couple with the bundle-server
  design (F-2). · **VERIFIED**
- [ ] **F-10** — Storage leaks metadata: plaintext key names (would expose the contact
  graph), unpadded ciphertext lengths, no `secure_delete`/rollback protection. Values
  themselves are encrypted correctly. Decide hardening scope at audit. · **VERIFIED**
- [ ] **F-15 (metadata)** — Solana RPC path bypasses Tor by design, linking the user's
  IP to on-chain PSI activity. Traffic-analysis review over the Tor boundary is an
  audit-level concern. · **NEEDS-HOME**

---

## HOME-ONLY
*Devnet deploy / device / open network / Android tooling. Not security blockers by
themselves, but required for a working build.*

- [ ] **F-14** — `declare_id!` placeholder; `psi_intersect_callback` only logs (no result
  delivery to client); dead `submit_query` still burns nonce state. · **NEEDS-HOME**
- [ ] **F-15 (wiring)** — `TorTransport::new` ignores `_state_dir`; Tor guard/state must
  live in the app sandbox. · **NEEDS-HOME**
- [ ] **F-16** — Raw X25519 output fed to `RescueCipher` without an explicit KDF — verify
  `@arcium-hq/client` derives internally at devnet integration. · **NEEDS-HOME**
- [ ] **lutOffset = BN(0)** placeholder (`program.ts:172`) — fix after MXE deploy.
- [ ] **CIRCUIT_HASH** refresh from a fresh `arcis build` (must follow F-3).
- [ ] **L-4** — `ChatScreen.kt:70` decodes ciphertext as UTF-8 — coupled to FFI wiring.
- [ ] **F-12** — Kotlin `ratchetEncrypt`/`ratchetDecrypt` stubs return plaintext; make
  them fail closed (`NotImplementedError`) like `BluetoothMeshManager`. (Android scope.)
- [ ] **core-FFI wiring** — `mobile-ffi` ↔ Kotlin UniFFI bindings + `.so` build.

---

## EXTRA-SCAN (read-only verification pass, 2026-06)
*Targeted re-scan beyond the 17 findings. Report only — nothing fixed.*

- **`pull_request_target`:** none. Every review workflow (security/karpathy/pi/graphify)
  triggers on `pull_request`, so fork PRs do not receive `secrets`. ✓ **VERIFIED**
- **Secrets in logs:** no workflow echoes `secrets.*` to stdout; the F-5 gate logs were
  inspected on PR #28 and print only status lines, not key material. ✓ **VERIFIED**
- **Unpinned `@latest` installs in CI** (supply-chain surface, subset of F-5):
  - `pi-review.yml`: `npm install -g @earendil-works/pi-coding-agent` — no version.
  - `graphify.yml`: `pip install graphifyy` — no version. *(double-check this exact
    package name is intended — it runs arbitrary code and receives the API key.)*
  - `arcium-ci.yml` (core-rust): `cargo install cargo-audit --locked` — no version.
  - `arcium-ci.yml` (ts-crypto): `npm install` (a `package-lock.json` exists; prefer
    `npm ci` for reproducibility).
- **Crypto TODO/FIXME hinting at an unfinished security path:** none new. Only the
  cosmetic `"TODO.onion"` placeholder in `core-transport` and the already-tracked
  `rescue.rs` STUB / M-3 references in `contact_hash.rs`. ✓ **VERIFIED**

---

## F-5 pin manifest (mechanical — do in a networked session)
Sandbox has no network (403 allowlist) and the GitHub MCP is scoped to this repo only,
so tag→commit-SHA resolution is **not possible here**. Do NOT guess SHAs. In a session
with network, resolve each ref to a full 40-hex commit SHA (e.g.
`gh api repos/<owner>/<repo>/git/refs/tags/<tag>`), pin `uses: owner/repo@<sha> # <tag>`,
and verify CI still passes.

| Workflow | Action ref to pin | Note |
|----------|-------------------|------|
| security-review | `actions/checkout@v4`; `anthropics/claude-code-security-review@main` | `@main` is the highest-risk mutable ref |
| karpathy-review | `actions/checkout@v4`; `anthropics/claude-code-action@beta` | `@beta` mutable |
| pi-review | `actions/checkout@v4`; `actions/setup-node@v4`; `actions/github-script@v7` | + version-pin `@earendil-works/pi-coding-agent` |
| graphify | `actions/checkout@v4`; `anthropics/claude-code-action@beta` | + version-pin `graphifyy` |
| arcium-ci | `actions/checkout@v4`; `actions/setup-node@v4`; `arcium-hq/setup-arcium@v0.10.4` | + pin `cargo-audit`; prefer `npm ci` |
| android-ci | `actions/checkout@v4`; `actions/setup-java@v4`; `actions/github-script@v7`; `actions/upload-artifact@v4` | Android scope |
| monthly-backup | `actions/checkout@v3`; `actions/create-release@v1`; `actions/upload-release-asset@v1` | **both release actions are archived/unmaintained — replace** (e.g. `softprops/action-gh-release` pinned by SHA, or `gh release create`) |

---

*Crypto fixes F-1 / F-2 / F-3 are NOT bundled here — each is a separate PR after the
owner reviews the findings table and the diff. This document only tracks scope and
priority.*
