# Threat checklist

What to check, area by area. Paths say where each area lives; they drift, so
re-derive before citing (`find crates -name '*.rs'`, `ls .github/workflows`,
`grep -rn`). The permanent crypto rules are in `CLAUDE.md` and are referred to,
not repeated. Open findings are in `docs/SECURITY-FINDINGS.md`.

A question here is a prompt to read the code, not a finding. A finding needs the
attack path described in `SKILL.md`, step 5.

## 1. Messaging crypto

Where: `crates/core-crypto/src/` — `x3dh.rs`, `ratchet.rs`,
`ratchet/checkpoint.rs`, `hybrid.rs`, `spk_id.rs`, `session_handle.rs`.

- **Layer separation.** Messages use XChaCha20-Poly1305 and the Double Ratchet;
  PSI uses only RescueCipher (`CLAUDE.md`). Any use of `rescue` on the message
  path, or of a message AEAD in PSI code, is a finding.
- **X3DH.** Is the signed prekey still verified over its domain-separated
  object? Is the associated data still initiator identity key then responder
  identity key? The Ed25519 signing key is bound to the X25519 identity key by
  the pinned contact card, not by the bundle (F-2); one-time prekeys are not
  enforced single-use (F-13). A change to the AD, a KDF `info` string, a
  version or cipher-suite byte, or the handshake layout is a protocol change.
- **KDF and domain separation.** Every HKDF `info` label and domain constant
  serves one purpose; a new derivation reuses none. Truncation width and byte
  order are deliberate — see the module notes in `session_handle.rs` and
  `spk_id.rs`.
- **Double Ratchet.** The header is bound as AEAD associated data. `decrypt`
  mutates state on a snapshot and restores it on any error (F-1): a new early
  return or `?` between mutation and authentication breaks that. Skipped keys
  are indexed by (DH public key, n), bounded by `MAX_SKIP` and
  `MAX_SKIPPED_KEYS`, and zeroized on eviction.
- **Counter exhaustion.** `ns`, `nr`, `pn` are `u32`. Check the arithmetic, and
  check the root `Cargo.toml` release profile for `overflow-checks`: without it
  an unchecked `+= 1` wraps silently in release builds.
- **Nonces.** No (key, nonce) pair is ever reused. Two live copies of one
  ratchet state encrypt under the same message key and counter
  (`ratchet/checkpoint.rs` module notes); anything that makes a second copy
  outside the durable session is a finding.
- **Message identity.** The message id is a domain-separated hash of the exact
  wire bytes (`core-protocol/src/messaging.rs`). Deduplication, receipts or
  history keyed by anything else — a client id, a relay sequence number — needs
  a stated reason.
- **Replay.** A replayed wire message is recognised as a duplicate or rejected,
  never accepted as new — including after a restart and after its skipped key
  has been used.
- **Zeroization.** Root, chain and message keys, identity secrets, decrypted
  blobs and plaintext buffers are wiped on every exit path, including errors
  and unwinding. Watch for new `Clone`, `Copy` or `Debug` on secret types, and
  for secrets reaching `format!`, error values or logs.

## 2. Durable state

Where: `crates/core-protocol/src/` — `durable.rs`, `checkpoint.rs`,
`messaging.rs`, `messaging/`; `crates/core-storage/src/lib.rs`. Specification:
`docs/S2-B2-DURABLE-MESSAGING.md`. Load `mbr-integration` alongside.

- **Transactional ordering.** The new session state and the operation's
  outbox or inbox record commit in one conditional transaction, and the output
  (ciphertext or plaintext) is released only after the commit is reported. A
  path that releases output earlier, or commits state without its record, is a
  finding.
- **Checkpoint consistency.** The predecessor check (binding, role, generation,
  record hash) runs inside the same write transaction. A check made before
  `BEGIN` is a time-of-check/time-of-use gap.
- **Ambiguous COMMIT.** An error reported after `COMMIT` may still have been
  durable. Does the caller treat it as "maybe committed" and refuse to stage
  again from the older state?
- **Duplicate application.** Inbox delivery is at least once. Every consumer
  must be idempotent by message id.
- **Stale instance / ABA.** A removed and recreated session restarts at
  generation 0; a transition staged from the old one must fail. Any cache of
  session state across operations reopens this.
- **Generation and session binding.** On load, the record's identity keys and
  role are checked against what the caller asked for.
- **Rollback.** The store has no rollback protection, and says so. A change
  must neither rely on it nor claim it.
- **Retry.** A retry republishes stored bytes. A retry path that encrypts again
  creates a second ciphertext for one logical message.
- **Crash boundaries.** For each new write, state what exists if the process
  dies before it, between its statements and after it. The crash tests in
  `core-protocol/src/messaging/tests/` and `mobile-ffi/src/tests/` show the
  existing pattern.

## 3. Identity

Where: `crates/mobile-ffi/src/contacts.rs`, `crates/core-crypto/src/x3dh.rs`,
the Android contact-card and add-contact code. Specification:
`docs/NET-MESSAGING.md` §2, and §6a of the S2-B2 specification for removal.

- **Contact-card binding.** A card names both identity keys (X25519 and
  Ed25519). A pinned card is never replaced; a different card for the same
  X25519 key is refused.
- **Identity substitution.** A prekey bundle or handshake that names keys other
  than the pinned ones is never used.
- **TOFU boundary.** Trust comes only from the user's out-of-band fingerprint
  comparison. Anything the relay supplies — bundles, the envelope's sender
  field — is untrusted.
- **Handshake authentication.** An incoming handshake is checked against the
  pinned keys before any session is created.
- **Session replacement and reset.** Who can cause a session to be removed or
  replaced? A remote party must not be able to reset one by sending a new
  handshake; local removal follows the S2-B2 §6a rules.

## 4. Network

Where: `crates/mobile-ffi/src/network.rs`, `network/wire.rs`,
`network/chat.rs`, `crates/relay/`. Specification: `docs/NET-MESSAGING.md`.

- **Receipts.** A text is delivered only when an authenticated receipt inside
  the ratchet names its exact message id. A forged or replayed receipt, one
  from another session, or the relay accepting the message must not mark it
  delivered.
- **Cross-session substitution.** The envelope's sender field is
  unauthenticated and only selects a session. A message must fail to decrypt
  under any other session; the AD binds both identity keys.
- **Malformed input.** Envelope, payload and relay frames decode exactly — no
  trailing bytes, lengths within `MAX_FRAME`, counts at least one — and never
  panic or allocate from an attacker-chosen length.
- **Relay trust boundary.** The relay can drop, reorder, replay, duplicate and
  delay, and sees metadata. Confidentiality, integrity and delivery status must
  not depend on its honesty.
- **Metadata exposure.** What new metadata does the change show the relay or
  the network: sizes, timing, recipient keys, the sender field? The
  development relay has no TLS and no Tor, so nothing may claim anonymity for
  it (F-15).
- **Retransmission identity.** A retransmission carries identical bytes and so
  the same message id.
- **Offline and recovery.** After lost network, lost relay or process death:
  nothing committed is lost, nothing is shown twice, and nothing is encrypted
  twice.

## 5. Android and FFI

Where: `crates/mobile-ffi/`, the UniFFI bindings generated at build time,
`android/app/src/main/`. Load `android-uniffi-bridge` for how the bridge is
built.

- **FFI ownership.** Every `unsafe` block, raw pointer or handle lifetime —
  including use after close.
- **Secret copies.** Secrets that reach Kotlin (`ByteArray`, `String`) cannot
  be wiped reliably. Private keys must not cross the boundary; a new FFI
  function that returns secret material needs a stated reason.
- **Lifecycle and restart.** Process death at any point, Activity recreation,
  service restart: Kotlin state must be rebuildable from the Rust store.
- **Generated bindings.** They are generated, not edited. A hand edit is lost
  or disagrees with the `.so`.
- **Kotlin authority.** Kotlin must not decide cryptographic or session state:
  which session a message belongs to, whether it was delivered, whether it is
  a duplicate. Rust decides. No Kotlin stub may return a value that could be
  mistaken for a real result (F-12).
- **Platform settings.** `allowBackup`, exported components, cleartext traffic,
  debug-only features reachable in release, `Log.*` of message content or keys,
  and the master-key wrapping in AndroidKeyStore, which must fail loudly rather
  than silently regenerate.

## 6. Arcium / PSI

Where: `arcium-psi/programs/arcium-psi/src/lib.rs`,
`arcium-psi/encrypted-ixs/src/lib.rs`, `arcium-psi/tests/src/`,
`crates/core-crypto/src/contact_hash.rs` and `rescue.rs`.

- **RescueCipher only for PSI.** Never for messages. The Rust RescueCipher is
  a stub (M-3); nothing may present it as real.
- **Contact hash.** Both sides must compute the canonical form in `CLAUDE.md`,
  and the cross-language parity test must still cover it.
- **Account authorization.** Signer checks, `has_one`, owner-derived PDA seeds
  and the monotonic nonce hold for every instruction.
- **PDA and account substitution.** Every account's address or seeds are
  constrained; each `UncheckedAccount` has a stated reason.
- **Callback authorization.** Only the Arcium computation callback can invoke
  the callback, and its output is bound to the query that started it.
- **Circuit source and hash.** `OffChainCircuitSource` keeps only the hash on
  chain, and that hash is the SHA-256 of `psi_intersect.arcis.ir`, not a git
  SHA (`CLAUDE.md`). A circuit change changes the hash and every constant that
  pins it.
- **Open findings.** Server-dataset anchoring (F-4) and padding false positives
  (F-3): say whether the change touches them.

## 7. General

- **Supply chain.** New or changed dependencies and lockfiles (Cargo, npm,
  Gradle); `uses:` not pinned to a commit SHA; install scripts; `curl | sh`;
  new ignores in `.cargo/audit.toml`.
- **Unsafe Rust.** Every new `unsafe` states the invariant that makes it sound.
- **Secret logging.** `println!`, `dbg!`, `log`, `Log.d`, panic and error
  messages that could carry keys, plaintext or the master key.
- **Credentials.** Tokens, keys, `.env` files or keystores in the diff; new
  `secrets.*` in workflows. GitHub CI must not use a paid LLM provider key
  (`CLAUDE.md`).
- **Insecure defaults.** A permissive default, or a development-only path
  reachable in a release build.
- **Test masking.** `#[ignore]`, deleted or weakened assertions, tests that no
  longer run, test filters that match nothing.
- **False-green CI.** A step that exits 0 without doing what it claims:
  `continue-on-error`, `|| true`, a swallowed exit code in a pipe without
  `pipefail`, a path filter that keeps a relevant job from firing. The
  "tests actually ran" guards in `.github/workflows/arcium-ci.yml` show the
  pattern to expect.
