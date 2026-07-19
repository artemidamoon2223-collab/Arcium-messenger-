> **Historical review — imported for durable reference.**
>
> Originally authored **2026-06-09** as a read-only, report-only deep security
> review (commit `d46f6eb`, branch `claude/arcium-security-deep-review-inlyr2`,
> which was never merged to `main`). Imported into `main` verbatim on
> **2026-07-19** so the F-1…F-17 finding definitions are durable and don't
> depend on an unmerged branch that could disappear.
>
> **This document is preserved exactly as originally written. Its status
> language ("open", "not yet fixed", severity framing, the fix-order
> plan, etc.) reflects the repository state on 2026-06-09 and must NOT be
> read as current.** The authoritative, continuously re-verified status of
> every finding (F-1…F-17), each backed by a commit SHA / `file:line` /
> test name from the *current* `main`, lives in
> [`docs/SECURITY-FINDINGS.md`](./SECURITY-FINDINGS.md) — that tracker
> supersedes any status claim below. For example, **F-1** is described
> below as an unfixed HIGH-severity bug; it has since been fixed (see the
> tracker for the commit and passing regression tests).
>
> One scope note for context: "Scope: full repository at commit `40b35b3`"
> in the header below refers to *this review's own* baseline at the time
> it was written — not to `main`'s current HEAD.

---

# Deep Security Review — Arcium Messenger (2026-06)

**Scope:** full repository at commit `40b35b3` (branch base: `main`).
**Mode:** READ-ONLY review. No code was changed. Findings only; fixes are deferred to
separate PRs after triage with the owner.
**Method:** line-by-line read of all Rust crates, the Anchor program, the Arcis circuit,
the TS client, CI workflows, and a static read of Kotlin sources (no Android tooling).
Threat classes used: protocol bugs (X3DH / ratchet state / replay / OPK), nonce & key
misuse, memory hygiene / zeroization, PSI/MPC correctness, on-chain access control,
traffic analysis / metadata, FFI boundary, storage crypto, supply chain, CI integrity.

**Verification labels:**
- **VERIFIED** — the code path was read and the issue confirmed statically.
- **NEEDS-HOME** — confirmation requires devnet / device / open network.

---

## 1. Findings summary

| Severity | Count |
|----------|-------|
| CRIT     | 0     |
| HIGH     | 1     |
| MED      | 5     |
| LOW      | 6     |
| INFO     | 5     |
| **Total**| **17**|

---

## 2. Findings table

### F-1 · HIGH · Ratchet state is mutated before AEAD authentication → permanent session desync by an unauthenticated attacker
**File:** `crates/core-crypto/src/ratchet.rs:147-176` (`decrypt`), `:203-220` (`dh_ratchet_step`) · **VERIFIED**

`DoubleRatchet::decrypt` performs the DH ratchet step and advances the receiving
chain **before** `aead_decrypt` verifies the Poly1305 tag:

```rust
if need_dh {
    self.skip_message_keys(header.pn)?;
    self.dh_ratchet_step(PublicKey::from(header.dh))?;   // rk, dhs, cks, ckr replaced
}
self.skip_message_keys(header.n)?;
let (new_ckr, mk) = kdf_ck(&ckr);
self.ckr = Some(new_ckr);
self.nr += 1;
aead_decrypt(&mk, ciphertext, &full_ad)                  // authentication happens LAST
```

The header is bound to the ciphertext via AAD, so a forged message **fails to
decrypt** — but by then `dh_ratchet_step` has already overwritten `rk`, generated a new
`dhs`, and replaced both chains with values derived from the attacker's garbage DH key.

**Exploit scenario:** any network attacker (no keys required) sends one packet with a
random 32-byte `header.dh` and plausible `pn`/`n`. `decrypt` returns
`Err(Decryption)`, but the root key is now corrupted. Every subsequent legitimate
message from the real peer triggers another ratchet step on the corrupted `rk` and
fails to decrypt. The session is permanently destroyed; both sides must re-run X3DH.
One UDP/onion datagram = one killed session.

**Recommended fix (do not implement in this PR):** make `decrypt` transactional —
compute the trial ratchet step / skipped keys on cloned state (or local variables),
attempt `aead_decrypt`, and commit the new state **only on success**. This is the
standard hardening over the Signal-spec pseudocode (which has the same shape but is
explicitly documented as needing transactional state in real implementations).
Add a regression test: garbage header + garbage ciphertext, then assert a legitimate
follow-up message still decrypts.

---

### F-2 · MED · X3DH: no binding between the Ed25519 signing key and the X25519 identity key
**File:** `crates/core-crypto/src/x3dh.rs:16-22, 37-39, 59-61` · **VERIFIED**

`PrekeyBundle` carries an independent `signing_pk: VerifyingKey` next to
`identity_pk: PublicKey`. The SPK signature is verified against `signing_pk`, which is
itself delivered **inside the same untrusted bundle**, and nothing cross-signs or
derives one key from the other (Signal solves this with XEdDSA: identity key == signing
key). The AD (`our_identity_pk || bob.identity_pk`) also excludes `signing_pk`.

**Exploit scenario:** a malicious key server replaces the whole bundle (its own
`identity_pk`, `signed_prekey_pk`, and its own `signing_pk` + valid self-signature).
`x3dh_initiate` accepts it — the signature check provides zero authentication, only
integrity *within* the attacker-chosen bundle. MITM then proceeds normally. Out-of-band
fingerprint verification can only catch this if the fingerprint covers `signing_pk` as
well as `identity_pk`, and no such convention is defined anywhere in the repo.

**Recommended fix:** bind the keys — either adopt XEdDSA-style identity (sign with a
key convertible to/from the X25519 identity key), or require the identity key to sign
the signing key (cross-certification) and include `signing_pk` in the AD and in the
out-of-band fingerprint definition. Document the trust model in `x3dh.rs`.

---

### F-3 · MED · PSI zero-padding produces false-positive matches on padding slots
**File:** `arcium-psi/tests/src/client.ts:24-25` + `arcium-psi/encrypted-ixs/src/lib.rs:51-64` · **VERIFIED** (logic) / **NEEDS-HOME** (end-to-end on devnet)

The client pads short batches with `0n`:

```ts
const padded = phoneHashes.slice(0, BATCH_SIZE);
while (padded.length < BATCH_SIZE) padded.push(0n);
```

The circuit compares every client slot against every server slot
(`client.hashes[i] == server.hashes[j]`). If the server side pads its set the same way
(there is no other padding convention defined in the repo), then **every padded client
slot matches every padded server slot**: `0 == 0 → matches[i] = true`. A user with 3
contacts querying a server with a non-full batch gets `true` for slots 3..9 —
`decryptResult` maps them to "contact registered".

**Exploit/impact scenario:** correctness, not key compromise — but it fabricates
contact-discovery results, and an app acting on them (e.g. auto-creating sessions)
behaves on attacker-predictable garbage. Also note: a real phone whose truncated hash
happens to be `0` is indistinguishable from padding (negligible probability, 2⁻⁶⁴).

**Recommended fix:** pad each side with per-side random distinct sentinels (e.g.
client pads with random u64s, server with different random u64s) or carry an
explicit `count` field inside the encrypted struct and mask results `i >= count` in the
circuit. Must be fixed *before* CIRCUIT_HASH is frozen — it changes the circuit or the
client convention.

---

### F-4 · MED · `submit_psi_query`: the "server" dataset is supplied and encrypted by the same caller — no on-chain anchoring of the server set
**File:** `arcium-psi/programs/arcium-psi/src/lib.rs:52-117` · **VERIFIED**

Both `client_data` **and** `server_data` are instruction arguments provided by the one
`user: Signer`. No account constraint binds `server_data` to a registry account, a
server authority, or a stored commitment. The instruction's only validation is
non-zero encryption keys.

**Exploit scenario:** PSI's privacy story assumes two mutually distrusting input
owners. Here the querying client fabricates the "server set" freely, so the result
proves nothing to anyone, and a real deployment that later trusts these results (e.g.
the server believing match flags) can be fed arbitrary intersections. Conversely there
is no path for the *real* server set to enter the computation at all.

**Recommended fix:** at MXE deploy time, source `server_data` from an on-chain account
written by the server authority (PDA with `has_one = server_authority`), or store a
commitment (hash) the instruction verifies. Design decision needed before devnet
deploy; flagging now so it lands in the home-sprint plan.

---

### F-5 · MED · Supply chain: unpinned GitHub Actions and unpinned package installs in workflows that hold `ANTHROPIC_API_KEY`
**Files:** `.github/workflows/security-review.yml:26` (`anthropics/claude-code-security-review@main`),
`karpathy-review.yml:25` (`anthropics/claude-code-action@beta`),
`pi-review.yml:27` (`npm install -g @earendil-works/pi-coding-agent`, no version),
`graphify.yml:21` (`pip install graphifyy`, no version), `graphify.yml:28` (`claude-code-action@beta`),
`monthly-backup.yml` (`actions/create-release@v1`, `upload-release-asset@v1` — both archived/unmaintained, `checkout@v3`) · **VERIFIED**

`@main` / `@beta` are mutable refs: a compromised or malicious update to any of these
actions executes in a job that has `secrets.ANTHROPIC_API_KEY` and (for the review
workflows) a `pull-requests: write` token. The same applies to the unpinned
latest-version npm and pip installs — `pip install graphifyy` is especially worth a
double-check that this exact package name is the intended one, since it both runs
arbitrary code and receives the API key.

Mitigating factor: all three review workflows trigger on `pull_request` (not
`pull_request_target`), so fork PRs don't get secrets. The exposure is to upstream
compromise of the actions/packages themselves, which is exactly what SHA pinning
addresses.

**Recommended fix:** pin every third-party action to a full commit SHA
(`uses: owner/repo@<40-hex-sha>` with a version comment), pin
`@earendil-works/pi-coding-agent@<exact version>` and `graphifyy==<exact version>`,
and replace the archived `actions/create-release@v1` / `upload-release-asset@v1` with
`softprops/action-gh-release` pinned by SHA (or `gh release create`).

---

### F-6 · MED · `hybrid_encaps` panics on malformed peer public key — DoS at the future FFI boundary
**File:** `crates/core-crypto/src/hybrid.rs:81-86` · **VERIFIED**

```rust
let ek_key: Key<EncapsulationKey768> = pk.ml_kem.as_slice().try_into()
    .expect("valid encapsulation key bytes");
let ek = EncapsulationKey768::new(&ek_key).expect("valid key");
```

`pk.ml_kem` originates from a *peer's* bundle (attacker-controlled length/content).
A wrong-length or invalid encapsulation key panics instead of returning an error.
Today `hybrid_*` is not yet exported through UniFFI, so severity is contained; the
moment it is wired into the bundle-processing path, any peer can crash the app with a
malformed bundle (UniFFI converts panics into a generic unexpected-error/abort path —
either way it is a remote-triggerable failure, and `expect` text patterns can mask
real validation).

**Recommended fix:** change `hybrid_encaps` to return `Result<_, HybridError>` and
map both conversions to `Err(HybridError)` (mirroring `hybrid_decaps`, which already
does this correctly at lines 105-114).

---

### F-7 · LOW · Hybrid KEM combiner does not bind ciphertexts/public keys into the KDF
**File:** `crates/core-crypto/src/hybrid.rs:120-128` · **VERIFIED**

`combine_secrets` derives the shared secret as
`HKDF(x25519_ss || ml_kem_ss, info="HybridKEM/v1")`. Modern hybrid constructions
(X-Wing; draft-ietf-tls-hybrid-design) additionally bind the ML-KEM ciphertext and the
public keys into the KDF input so the final secret is committed to the exact
transcript — without it, ML-KEM's lack of ciphertext binding (it is not a committing
KEM) can enable re-encapsulation/mix-and-match games in composed protocols.
Not exploitable in the current standalone usage, but cheap to fix before the format
ships and freezes.

**Recommended fix:** include `ml_ct`, `eph_pk`, and recipient public keys in the HKDF
input (or adopt the X-Wing combiner verbatim).

---

### F-8 · LOW · Memory hygiene: transient secret copies not zeroized
**Files:** `crates/core-crypto/src/x3dh.rs:108-121`; `crates/core-crypto/src/ratchet.rs:132-145, 147-176, 262-276`; `crates/core-crypto/src/hybrid.rs:54-68, 109-111`; `crates/mobile-ffi/src/lib.rs:61-64, 81-93` · **VERIFIED**

Spots where key material outlives its use in non-zeroized memory:
- `x3dh::derive_root` — the `ikm` Vec concatenating all DH outputs (the master secret
  of the handshake) is dropped without zeroization (`x3dh.rs:109-116`).
- `ratchet::kdf_ck` and its callers — `mk`/chain-key stack copies in
  `encrypt`/`decrypt`/`skip_message_keys` are dropped unzeroized; the skipped-key map
  and long-lived fields are handled (L-1/L-3), the transients are not.
- `hybrid_keygen` — `seed_bytes` stack copy of the ML-KEM seed survives after being
  copied into the (zeroizing) `HybridSecretKey`; same for the `seed_bytes` copy in
  `hybrid_decaps:109`.
- `mobile-ffi::load_identity` — the decrypted 64-byte identity blob (`bytes`) and the
  `sk_bytes`/`dh_bytes` copies are not `Zeroizing` (contrast with `save_identity`,
  which was fixed in M-2); `ArciumCore::new` drops the caller's `master_key` Vec
  without wiping (`lib.rs:62`).

Individually minor (same-process memory disclosure needed), but this is the class the
project already committed to handling (L-1/L-2/L-3). One sweep with
`Zeroizing`/explicit `zeroize()` closes all of them.

---

### F-9 · LOW · `load_identity`: panics on poisoned mutex and silently masks wrong-key decryption as "no identity"
**File:** `crates/mobile-ffi/src/lib.rs:80-94` · **VERIFIED**

- `self.store.lock().unwrap()` (line 81) panics across the FFI boundary on a poisoned
  mutex — the exact case M-2 fixed in `save_identity` five lines above.
- `Err(_) => return None` collapses `StorageError::Decryption` (wrong master key,
  corrupted DB) into the same `None` as `NotFound`. An app layer that interprets
  `None` as "first run" will generate and save a fresh identity, silently destroying
  the user's real identity and breaking all sessions — a state-loss bug with security
  consequences (peers see a key change they may be socially engineered to accept).

**Recommended fix:** return `Result<Option<Arc<Identity>>, CoreError>` so wrong-key is
distinguishable, and handle the poisoned mutex like `save_identity` does.

---

### F-10 · LOW · Storage: plaintext key names, sizes, and update patterns leak metadata; no rollback or secure-delete
**File:** `crates/core-storage/src/lib.rs:40-44, 59-99` · **VERIFIED**

Values are well protected (per-key HKDF subkey, random 24-byte nonce, key name as AAD).
What remains observable to anyone with the SQLite file:
- **Key names in plaintext** (`kv.k TEXT PRIMARY KEY`): conventions like
  `contact:alice` / `session:<id>` would expose the contact graph directly. Today only
  `identity/v1` is written, but `list_keys_with_prefix` exists precisely to enable
  such naming.
- **Ciphertext lengths** (no padding) reveal plaintext sizes; row count reveals
  contact/session counts; SQLite freelist/WAL retains old ciphertexts after
  `delete`/overwrite (no `secure_delete`, no `VACUUM`), and there is no rollback
  protection (an attacker with disk write access can revert individual values).

**Recommended fix (home):** HMAC/hash the key names with a master-key-derived key
(keep the prefix structure inside the MAC input), enable
`PRAGMA secure_delete=ON` (and consider `auto_vacuum`), and document the local-attacker
model. Padding and rollback counters are optional hardening, decide at audit.

---

### F-11 · LOW · CI integrity: `arcium test` failure is swallowed; dead `CLAUDE_SUCCESS` check; Pi reviews a truncated diff
**Files:** `.github/workflows/arcium-ci.yml` (job `arcium-test`: `arcium test || echo ...`), `karpathy-review.yml` (gate step references `${CLAUDE_SUCCESS:-}` which no step ever sets), `pi-review.yml` (`git diff ... | head -500`) · **VERIFIED**

- The `arcium-test` job can never go red: `arcium test || echo "..."` converts every
  integration failure into success. This is exactly the false-green pattern PR #25
  eliminated elsewhere. If the job is informational by design, name/mark it so;
  otherwise drop the `|| echo`.
- The karpathy gate's `[ "${CLAUDE_SUCCESS:-}" = "false" ]` branch is dead code — the
  variable is never exported; the `outcome` check is what actually gates.
- Pi receives only the first 500 lines of the diff: any PR larger than that is
  partially reviewed while still reporting a verdict. State the truncation in the
  comment or raise/remove the limit.

---

### F-12 · LOW · Kotlin crypto stubs return plaintext as "ciphertext"
**File:** `android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt` (`ratchetEncrypt`/`ratchetDecrypt` return their input) · **VERIFIED**

`BluetoothMeshManager.sendToPeer` does the right thing — `Result.failure(NotImplementedError(...))` —
but `ratchetEncrypt` returns the plaintext unchanged. Any future wiring of
send-path code against this stub ships plaintext silently and every test of "encrypt
then send" still passes. Fail closed: throw `NotImplementedError` like the mesh
manager. (Static read only; no Android tooling used, per scope.)

---

### F-13 · INFO · X3DH details: SPK signature lacks domain separation; OPK single-use is unenforced
**File:** `crates/core-crypto/src/x3dh.rs:37-39, 77-88` · **VERIFIED**

- The signature covers the raw 32 bytes of the SPK with no context label
  (`signing_pk.verify(bob.signed_prekey_pk.as_bytes(), ...)`). Any other place this
  Ed25519 key ever signs a 32-byte value becomes cross-protocol-confusable with a
  prekey endorsement. Sign `"X3DH-SPK-v1" || encode(spk)` instead (coordinate with F-2).
- `x3dh_respond` accepts `Option<&StaticSecret>` for the OPK; nothing at any layer yet
  tracks or deletes used OPKs, so replay of Alice's first message re-derives the same
  session (standard X3DH caveat — the enforcement layer simply doesn't exist yet).
  Must land together with the bundle-server design.

---

### F-14 · INFO · On-chain placeholders and result-delivery gap (pre-deploy state)
**File:** `arcium-psi/programs/arcium-psi/src/lib.rs:5, 119-142, 19-30` · **VERIFIED** (state), **NEEDS-HOME** (behavior)

- `declare_id!("PSiArc1um1111111111111111111111111111111111")` is a placeholder; must
  be regenerated at deploy.
- `psi_intersect_callback` verifies the BLS signature ✓ but then only `msg!`-logs the
  client's encryption key — the encrypted match vector is not written to any account or
  event; the client-side retrieval path doesn't exist yet.
- Legacy `submit_query` ignores `encrypted_contacts` entirely (dead risk surface — fine
  while documented, but it burns the nonce/counter state for no effect; consider
  removing before deploy).
- Access control on the implemented instructions is otherwise sound: `init_user` PDA is
  payer-seeded; `submit_query` has `has_one = owner` + monotonic nonce;
  `init_psi_intersect_comp_def` authority semantics rest on the
  `init_computation_definition_accounts` macro (MXE-authority enforcement to be
  confirmed on devnet — NEEDS-HOME).

---

### F-15 · INFO · Traffic analysis: Solana RPC path bypasses Tor by design (currently a stub)
**Files:** `android/.../network/SolanaClient.kt` (direct `BuildConfig.SOLANA_RPC_URL`), `crates/core-transport/src/lib.rs:23-32` · **VERIFIED** (code state), **NEEDS-HOME** (design decision)

Messaging rides Tor (arti), but PSI submissions/polling will hit the Solana RPC over
clearnet, linking the user's IP to on-chain PSI activity (queries_made counter, tx
timing). Tor-ify RPC calls (arti SOCKS or onion-fronted RPC) or document the metadata
trade-off explicitly. Also in `core-transport`: `TorTransport::new` ignores its
`_state_dir` parameter and uses `TorClientConfig::default()` — Tor guard/state location
on Android needs to be inside the app sandbox (decide at FFI wiring).

---

### F-16 · INFO · TS client: raw ECDH output used directly as RescueCipher key
**File:** `arcium-psi/tests/src/client.ts:12-17, 28` · **VERIFIED** (code), **NEEDS-HOME** (library internals)

`computeSharedSecret` returns the raw X25519 point (`x25519.getSharedSecret`) and feeds
it to `new RescueCipher(sharedSecret)` without a KDF and without a contributory-behavior
check. If `@arcium-hq/client`'s RescueCipher derives internally (likely, matching the
Arcium protocol), this is fine — verify at devnet integration and add a comment; if
not, insert an HKDF step. Nonce discipline note: `encryptContacts`/`decryptResult`
take caller-supplied nonces; the production caller must guarantee per-query uniqueness
(tests reuse fixed nonces, which is fine for tests only).

---

### F-17 · INFO · Docs drift in CLAUDE.md
**File:** `CLAUDE.md` · **VERIFIED**

- The repo-structure tree omits `android/.../network/{BluetoothMeshManager,SolanaClient}.kt`,
  `ui/navigation/AppNavigation.kt`, `.github/workflows/{pi-review,graphify}.yml`, and
  `docs/` — exactly the kind of stale map that has caused confusion before.
- Workflow table lists 5 workflows; there are 7 on disk.
- `ml-kem = "0.3"` note vs actual `0.3.2` in `crates/core-crypto/Cargo.toml` (benign).
- Test counts re-verified this session: `cargo test --workspace` = **55 passed, 0 failed,
  1 ignored (Tor network test)** — matches CLAUDE.md. ✓

---

## 3. Domains confirmed clean

- **contact_hash.rs** — canonical encoding matches TS exactly (LE, first 8 bytes),
  cross-language test vector present on both sides, privacy model honestly documented. Clean.
- **core-protocol (SessionManager)** — trivial map; removed sessions are dropped →
  ratchet `Drop` zeroizes. Clean at current scope.
- **core-storage value crypto** — per-key HKDF subkeys, random XChaCha20 nonces, AAD
  binding key names, subkey zeroization, master-key zeroize on Drop, LIKE-escape in
  prefix listing. Clean (metadata caveats → F-10).
- **Ratchet crypto core** — KDF chain (HMAC 0x01/0x02), header-in-AAD binding, FIFO
  skipped-key cap with eviction zeroization, MAX_SKIP bound, fresh random nonces under
  one-time message keys. Sound — the flaw is state-commit ordering (F-1), not the crypto.
- **Arcis circuit logic** — O(n²) blind compare, result encrypted to client's key only;
  correct for its size. (Padding semantics → F-3 are a client-convention issue.)
- **Workflow secret scoping** — review workflows run on `pull_request`, not
  `pull_request_target`; no secrets to fork PRs; no secrets echoed to logs. Clean
  (pinning → F-5).
- **rescue.rs stub** — honest STUB labeling, not reachable from the message path, TS
  side uses the real `@arcium-hq/client` cipher. (Dead code by design — M-3.)

## 4. Status of known/deferred items

| Item | Status |
|------|--------|
| M-3 rescue.rs stub is dead code; real PSI path is TS `@arcium-hq/client` | **Still true** — `rescue.rs` unchanged stub; only TS client constructs `RescueCipher` |
| L-4 `ChatScreen.kt` decodes ciphertext as UTF-8 | **Still present** — `ChatScreen.kt:70` `Text(msg.ciphertext.decodeToString())` |
| `lutOffset = BN(0)` placeholder | **Still present** — `program.ts:172`, plus matching TODO in `scenarios.test.ts:117-118` |
| RUSTSEC-2025-0009 / RUSTSEC-2023-0071 ignores | **Still present & annotated** — `.cargo/audit.toml` with provenance/impact/revisit notes |
| CIRCUIT_HASH refresh from `arcis build` | **Still pending** — `scenarios.test.ts:19-20` TODO at devnet deploy |

## 5. Overall assessment

The codebase is in better shape than typical pre-audit messengers of this size: the
crypto layering rule (XChaCha20 for messages / Rescue for PSI) is respected, AAD
binding and zeroization of long-lived secrets are in place, storage value-encryption is
correct, and the CI gates were rebuilt to fail honestly. The one finding that must be
fixed before any real-world messaging is **F-1** — it is cheap for an attacker, fatal
to a session, and easy to fix transactionally. The X3DH identity-binding gap (F-2) and
the PSI padding semantics (F-3) should be settled *before* formats/circuit hash freeze,
because both change wire/circuit conventions. Everything else is hardening that fits
naturally into the planned home sprint.

## 6. Prioritized fix order for the home sprint

1. **F-1** ratchet transactional decrypt (commit state only after AEAD success) + regression test.
2. **F-3** PSI padding convention (random per-side sentinels or count field) — must precede CIRCUIT_HASH freeze and devnet deploy.
3. **F-2 (+F-13)** X3DH identity/signing key binding + domain-separated SPK signature + fingerprint definition — must precede bundle-server format freeze.
4. **F-5** SHA-pin all third-party actions and version-pin npm/pip installs (one mechanical PR, immediate supply-chain win).
5. **F-6 + F-9** error-instead-of-panic in `hybrid_encaps`; `load_identity` Result type + poisoned-mutex handling (both are small, both sit on the future FFI boundary).

Then: F-8 zeroization sweep, F-10 storage metadata (with FFI work), F-4 server-set
anchoring (with MXE deploy), F-11/F-12 CI + stub fail-closed, F-15/F-16 at devnet
integration.

---
*Review performed read-only in a sandboxed session (no network, no toolchain beyond
cargo/tsc). Items marked NEEDS-HOME require devnet, a device, or open network to
confirm behaviorally.*
