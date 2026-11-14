# Threat checklist

What to check, area by area. Paths say where each area lives; they drift, so
re-derive before citing (`find crates -name '*.rs'`, `ls .github/workflows`,
`grep -rn`). The permanent crypto rules are in `CLAUDE.md` and are referred to,
not repeated. `docs/SECURITY-FINDINGS.md` is a dated snapshot of finding status,
useful as leads and as the record of accepted residuals; it is not a live source,
and a row is re-checked against the source at the target SHA before it is cited.

A question here is a prompt to read the code, not a finding. A finding needs the
attack path described in `SKILL.md`, step 5.

## 1. Messaging crypto

Where: `crates/core-crypto/src/` — `x3dh.rs`, `ratchet.rs`,
`ratchet/checkpoint.rs`, `hybrid.rs`, `spk_id.rs`, `session_handle.rs`,
`refusal_mac.rs`.

- **Layer separation.** Messages use XChaCha20-Poly1305 and the Double Ratchet;
  PSI uses only RescueCipher (`CLAUDE.md`). Any use of `rescue` on the message
  path, or of a message AEAD in PSI code, is a finding.
- **X3DH.** Is the signed prekey still verified strictly over its
  domain-separated signed-prekey object, which is what binds the X25519
  identity key to the Ed25519 signing key (the F-2 binding)? Is the associated
  data still initiator identity key then responder identity key? Is each
  one-time prekey consumed at most once (F-13)? Read the tracker entries for
  F-2 and F-13 against the code before citing them: the tracker is a dated
  snapshot and its status has lagged the code before. A
  change to the AD, a KDF `info` string, a version or cipher-suite byte, or the
  handshake layout is a protocol change.
- **KDF and domain separation.** Every HKDF `info` label and domain constant
  serves one purpose; a new derivation reuses none. Truncation width and byte
  order are deliberate — see the module notes in `session_handle.rs` and
  `spk_id.rs`.
- **Handshake-refusal MAC.** `refusal_mac.rs` tags `HANDSHAKE_REFUSAL_V1` with
  HMAC-SHA256 under an HKDF key from the static X25519 of the two identity
  keys; its `info` names refuser then initiator, so the key for "A refuses B"
  is not the key for "B refuses A", and an all-zero (low-order) DH output
  gives no tag. Check that a change keeps the check for an all-zero DH output,
  the role-ordered `info`, the constant-time tag comparison
  (`verify_refusal_tag`) and the wiping of the derived key. Two limits are documented, not fixed: whoever holds the
  initiator's own identity secret can make a refusal it accepts
  (key-compromise impersonation, `docs/NET-MESSAGING.md` §8), and the
  static-DH MAC has not been reviewed by a cryptographer — the module says
  REVISIT AT SECURITY AUDIT. Neither may be described as settled.
- **Double Ratchet.** The header is bound as AEAD associated data. `decrypt`
  mutates state on a snapshot and restores it on any error (F-1): a new early
  return or `?` between mutation and authentication breaks that. Skipped keys
  are indexed by (DH public key, n), bounded by `MAX_SKIP` and
  `MAX_SKIPPED_KEYS`, and zeroized on eviction.
- **Counter exhaustion.** `ns`, `nr`, `pn` are `u32`. Two different things
  bound them, and a claim about one is not a claim about the other:
  - the raw `DoubleRatchet` increments with an unchecked `+= 1`; without
    `overflow-checks` in the root `Cargo.toml` release profile that wraps
    silently in release and panics in debug, so the raw type has no bound of
    its own;
  - the durable layer refuses to persist a state past the limit
    (`check_state`, `MAX_RESUMABLE_NR`, `ratchet/checkpoint.rs`), so a durable
    session rejects that transition instead of storing it.
  Check the arithmetic on any path that holds a raw ratchet, and check whether
  that path goes through the durable layer before relying on its bound.
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
  and unwinding. Watch for new `Clone`, `Copy` or `Debug` on secret types
  (`Zeroizing` derives `Debug` and prints its contents), and for secrets
  reaching `format!`, error values or logs. Secret-derived state inside
  `hmac`/`hkdf`/`sha2` values is not wiped and cannot be from this crate: that
  is a known residual (F-8, H-9); a new copy in Arcium's own code is not.

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
- **Forged or replayed refusals and handshakes.** A refusal restarts first
  contact (`take_refusal` → `restart_after_refusal`) only if its tag checks for
  the sender's pinned key and ours and it names the handshake of our own
  session with that sender, on which nothing was received yet; anything else
  is dropped (`docs/NET-MESSAGING.md` §6). A handshake is not authenticated
  where the network layer reads it: one naming a pinned contact while our
  session with that contact is an unconfirmed start of our own raises the
  conflict flag (the `Handshake` arm of `NetworkMessenger::process` in
  `network.rs`). So a forged or replayed
  handshake can raise a false conflict. Check what a resolve then does
  (`resolve_session_conflict` in `network/chat.rs`: committed texts
  `NotDelivered`, abandoned, our session removed, wait for the peer's
  handshake). A probe at `de328a1` showed that a resolved false conflict can
  dead-end the conversation for good: the contact accepts the original
  handshake while this device waits for one that never comes (recorded in
  the tracker by PR #160). A change must not let a forged or replayed object reach a
  restart or a session removal without either a verified refusal or the
  user's own resolve.

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
  the network: sizes, timing, recipient keys, the sender field? The relay path
  provides no anonymity, metadata protection or Tor (`NET-MESSAGING.md` §8),
  so nothing may claim them for it.
- **Retransmission identity.** A retransmission carries identical bytes and so
  the same message id.
- **Time bounds.** One relay request is bounded as a whole by
  `REQUEST_DEADLINE` (`crates/relay/src/client.rs`), one sync round by
  `ROUND_BUDGET`, and retransmission backs off by doubling up to
  `RETRANSMIT_CAP` (`network.rs`; `NET-MESSAGING.md` §7, R-4 and R-5 in the
  tracker). A new relay call or loop must stay under them: a per-syscall
  socket timeout does not bound a relay that trickles bytes. A round cut by
  the budget must lose and repeat nothing, and the budget line must not read
  as a network error. The tracker records what stays unbounded (the DNS
  lookup in `Connection::connect`).
- **What a mailbox reader learns.** Whoever can read a mailbox on the relay
  learns whom its owner has pinned: a message from a pinned sender without a
  session is kept (`NoSession` → `Fate::Keep`), one from a stranger is
  deleted, and refusals go only to pinned contacts (R-9, open;
  `NET-MESSAGING.md` §8). Check that a change adds no further keep/delete,
  answer/no-answer or timing difference that depends on who is pinned.
- **History numbering.** History entries are numbered without gaps and never
  deleted, so a number is missing only from a damaged store. At `de328a1`,
  paging (`chat_entries_page`), the summary and the one-time build of the
  open-entry record (`open_seqs`) fail on a missing number (`network/chat.rs`;
  R-10); PR #158 makes them skip it. A change that deletes, skips or reorders
  entry numbers, or reads them some other way, must say what happens to that
  assumption.
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
- **E.164 before hashing.** The hash input is the strict E.164 form
  (`normalize_e164`, hashed by `hash_contact_e164` in `contact_hash.rs`; TS
  `normalizeE164` in `arcium-psi/tests/src/utils.ts`; D-010). A number with no
  canonical form is refused, never hashed in another form, and no country is
  guessed. A change to the separators, the length or digit rules, or a new
  caller that hashes raw input with `hash_contact`, breaks matching between
  devices; both sides must still pass the shared vectors in
  `crates/core-crypto/tests/contact_hash_e164.tsv`.
- **Account authorization.** Signer checks, `has_one`, owner-derived PDA seeds
  and the monotonic query nonce hold wherever they apply.
- **PDA and account substitution.** Every account's address or seeds are
  constrained; each `UncheckedAccount` has a stated reason.
- **Callback authorization.** Only the Arcium computation callback can invoke
  the callback, and its output is bound to the query that started it.
- **Circuit source and hash.** `OffChainCircuitSource` keeps only the circuit
  URL and hash on chain. That hash is the SHA-256 of the compiled
  `psi_intersect.arcis` (what `arcium build` writes to
  `build/psi_intersect.hash`), not of `psi_intersect.arcis.ir` and not a git
  SHA (`CLAUDE.md`); the tests' `CIRCUIT_HASH` is the `.arcis.ir` hash, a
  version fingerprint. Both are program or test constants, so neither may come
  from an instruction argument. A circuit change changes both hashes, the URL
  and every constant that pins them.
- **Open findings.** Server-dataset anchoring (F-4) is open: say whether the
  change touches it. Padding false positives (F-3) are fixed (PR #118): each
  encrypted input carries its number of real entries (`count`) and only real
  slots are compared (`real_slots` in `arcium-psi/encrypted-ixs/src/lib.rs`).
  A change to `count` or `real_slots` changes the circuit and so its hash; a
  change to the client's padding or result check (`decryptResult` in
  `arcium-psi/tests/src/client.ts`) must keep the fix as well.

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
  `pipefail`, a path filter that keeps a relevant job from firing. Decide by
  what the step gates. A diagnostic `|| true` — tool versions, an
  `if: failure()` log dump after the real step has already failed the job —
  gates nothing and is not a finding. A masked required build, test, lint or
  audit step is one, and turning a blocking check advisory is forbidden
  (`CLAUDE.md`). The "tests actually ran" guards in
  `.github/workflows/arcium-ci.yml` show the pattern to expect.
