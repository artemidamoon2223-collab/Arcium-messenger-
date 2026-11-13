# Arcium state per MBR mechanism, and the proposed staging

Two parts, deliberately separated: **verified facts** about this repository, and
a **proposal** whose status is stated stage by stage. Do not quote a stage of
part 2 in the present tense unless part 1 shows it in the code.

Repository layout is not repeated here — see
`engineering-code-review/references/repo-map.md`. This file covers only what
bears on durable state.

## Re-derive before relying on any of this

Part 1 was checked against the source at `de328a1`. Rows point at files,
symbols and spec sections, not line numbers. The specs govern:
`docs/S2-B2-DURABLE-MESSAGING.md` (durable layer, "S2-B2 §n" below) and
`docs/NET-MESSAGING.md` (network layer and history, "NET §n"). Where code and
this file disagree, the code wins. Commands:

```bash
git log --oneline de328a1..HEAD -- crates/core-storage crates/core-protocol \
  crates/core-crypto/src/ratchet.rs crates/mobile-ffi \
  docs/S2-B2-DURABLE-MESSAGING.md docs/NET-MESSAGING.md   # empty = nothing below has moved
grep -n "PRAGMA" crates/core-storage/src/lib.rs                # durability set at open
grep -n "pub fn transaction\|pub fn commit\|pub fn rollback" crates/core-storage/src/lib.rs
grep -n "Messenger" crates/mobile-ffi/src/lib.rs               # the app's sessions go through the durable layer
grep -rn "SessionManager" crates/mobile-ffi/src                # empty = no in-memory session map in the app
grep -rn '"[a-z-]*:v1/' crates/*/src                           # versioned record keys
grep -n "const [A-Z_]*KEY: &str" crates/mobile-ffi/src/lib.rs  # identity and prekey records
grep -n "MAX_SKIP\|max_skipped\|fn trim_skipped" crates/core-crypto/src/ratchet.rs
grep -rni "CommitAnchor\|NullAnchor\|skip_age" crates           # empty = S6 and S7 not started
```

## Part 1 — verified state (category 1)

| MBR mechanism | Arcium status at `de328a1` | where it is |
|---|---|---|
| encrypted storage | **ALREADY** | XChaCha20-Poly1305 per value; key names stored as a master-key-derived hash (F-10). `core-storage/src/lib.rs`: module doc, `put_row` |
| single-write atomicity | **ALREADY** | `EncryptedStore::put` is one statement in `put_row` |
| **multi-write transaction** | **ALREADY** (S1) | `EncryptedStore::transaction` (`BEGIN IMMEDIATE`), `StoreTransaction::commit` / `rollback` |
| durable ratchet state | **ALREADY** (S2-B1, S2-B2) | checkpoints in `core-crypto/src/ratchet/checkpoint.rs` and `core-protocol/src/checkpoint.rs`; conditional commits in `core-protocol/src/durable.rs`; `Messenger` (`core-protocol/src/messaging.rs`) loads every session from the store and caches none. `ArciumCore` (`mobile-ffi/src/lib.rs`) holds a `Messenger`, and `mobile-ffi/src/messaging_api.rs` routes every messaging call through it. S2-B2 §1, §3. The in-memory `core_protocol::SessionManager` still exists; `mobile-ffi` does not use it |
| rollback on failed auth | **ALREADY** | `DoubleRatchet::decrypt` snapshots and restores, `core-crypto/src/ratchet.rs` (finding F-1) |
| duplicate rejection | **ALREADY** | the message id is checked against `inbox:` and `seen:` before the ratchet is touched (S2-B2 §6); the history keeps an index on message id (NET §10). At ratchet level as before (`skipped.swap_remove`) |
| skipped-key capacity bound | **PARTIAL** | `MAX_SKIP` per chain, `max_skipped` in total, `trim_skipped` evicts the oldest — `core-crypto/src/ratchet.rs` |
| skipped-key **age** expiry | **NOT** | no logical-time expiry; MBR uses `SKIP_AGE = 128` receives |
| immutable outbox / retry | **ALREADY** (S2-B2) | the `outbox:` record holds the exact wire bytes; `send_message` with a known client message id returns `AlreadyPending` and encrypts nothing; retransmission sends the stored bytes (S2-B2 §5; module doc of `mobile-ffi/src/network.rs`) |
| exact event identity | **ALREADY** | `core_protocol::messaging::message_id` = `SHA-256("ARCIUM-MESSAGE-ID-V1" ‖ wire)`, derived by both peers, never transmitted (S2-B2 §2) |
| ACK bound to an artifact | **ALREADY** (network layer) | a receipt inside the ratchet names the exact message id; only a receipt, or giving a session up (`resolve_session_conflict`, an accepted refusal), takes a text out of the outbox; `acknowledge_outgoing` is not exported through UniFFI (NET §5, §6). Application processing (`mark_read`) is not transmitted |
| rollback detection | **NOT** | owner decision D-009: v1 resists neither whole-file nor single-record rollback (S2-B2 §8, "Rollback decision") |
| bounded replay/history retention | **NOT** | `seen:` and `sendid:` records are kept for the life of the session and beyond (S2-B2 §8, "Retention"); history entries are never deleted (`mobile-ffi/src/network/chat.rs`, NET §10) |
| explicit states (MBR: PENDING/READY/BLOCKED/RETIRED) | **PARTIAL**, different shape | `ChatEntryState` and `ChatSessionState` (`network/chat.rs`), `TextState` (`network.rs`); an unresolved-commit flag kept in memory until `recover_session`, which returns public values only (`RecoveryReport`; S2-B2 §7). Not a mapping of the MBR enum |
| hardware-backed key provider | **PARTIAL** | `MasterKeyProvider.getOrCreateWrapKey` (`android/app/src/main/kotlin/com/arcium/messenger/security/MasterKeyProvider.kt`) requests only `PURPOSE_ENCRYPT or PURPOSE_DECRYPT` + GCM — no StrongBox, no attestation, no user-auth binding. Non-exportable, unverified security level |
| SOCKS "no direct fallback" rule | **NOT** (no Tor path) | the relay path is direct TCP (`relay::client::Connection::connect`); Tor is listed as not provided and kept as future work (NET §1, §8); `core-transport` (arti) has no production caller (F-15) |

Persisted records: the durable layer's record types are specified in S2-B2 §2;
the app adds its identity record (`mobile-ffi/src/lib.rs`), contact cards
(`mobile-ffi/src/contacts.rs`) and the history (`network/chat.rs`; its entry
keys use the namespace built by `entry_namespace`, which the `:v1/` grep above
misses). Use the greps for the current set rather than a list kept here.

Durability is set explicitly at open (`EncryptedStore::init`): `journal_mode =
DELETE`, `synchronous = EXTRA`, `busy_timeout = 5000`, `secure_delete = ON`,
pinned by the test `durability_configuration_is_pinned`. Power-loss durability
is still assumed, not demonstrated: it depends on the device honouring `fsync`
on files and directories (S2-B2 §8).

`local_session_handle` is **little-endian** by in-crate convention
(`core-crypto/src/session_handle.rs`) and is local-only; `spk_id` is
big-endian because it goes on the wire (`core-crypto/src/spk_id.rs`). Never
model one on the other.

## Part 2 — proposed staging (category 3)

Dependency order, not priority. No stage is authorized by this file.

Status at `de328a1`, from part 1: **S1** is implemented (transaction API; S2-B2
later set the PRAGMAs explicitly). **S2** is implemented: S2-B1
(`core-crypto`/`core-protocol`, PR #87) and S2-B2 (PRs #93, #94). **S3** and
**S4** are covered by S2-B2 (outbox, message id, receive committed with its
inbox record; S2-B2 §3, §5, §6). **S5** exists only partly and in a different
shape (the explicit-states row); it has not been assessed against this
proposal. **S6, S7 and S8 are not implemented.**

| # | stage | modules | prerequisite |
|---|---|---|---|
| S1 | transactional API for `EncryptedStore`; set PRAGMAs explicitly | `core-storage` | — |
| S2 | durable ratchet checkpoint; store becomes authority, memory a cache | `core-crypto`, `core-protocol`, `mobile-ffi` | S1 |
| S3 | immutable outbox + event identity + `retry()` that never encrypts | `mobile-ffi`, Kotlin | S2 |
| S4 | atomic receive acceptance in the same transaction | `mobile-ffi`, Kotlin | S2 |
| S5 | explicit states + recovery handles returning public data only | FFI, Kotlin | S3, S4 |
| S6 | skipped-key age expiry | `core-crypto` | — |
| S7 | `CommitAnchor` trait + `NullAnchor` default, witness behind a flag | new crate | owner decision |
| S8 | read-only security-event stream (future SOMA) | `mobile-ffi`, Kotlin | S5 |

**S1–S4 is the minimum that delivers value** without any authority: sessions
survive a crash, messages are not lost, none is applied twice, and a retry never
burns a generation.

Proposed send ordering, for evaluating any such change:

```
lock → BEGIN → derive next state (not yet installed) → encrypt
     → write {ratchet, outbox row} → COMMIT
     → install in memory → return artifact to caller
```

The artifact is published only after the commit. Crash before `COMMIT`: nothing
changed, generation not consumed, safe. Crash after `COMMIT` before return: the
artifact is recoverable from the outbox by event id — never re-encrypted.
S2-B2 implements this order without the in-memory step, since nothing is
cached (S2-B2 §3).

## Known risks to check in any MBR-shaped diff

1. **Two authorities.** Does Kotlin gain state, or a callback inside the commit
   boundary? Both are refusals.
2. **Un-zeroized secrets.** Serializing ratchet state puts the root key and
   chain keys in a byte buffer. Without `Zeroizing` that is a regression against
   the wiping key types of `DoubleRatchet` (`core-crypto/src/ratchet.rs`, the
   `Zeroizing` aliases and `ZeroizeOnDrop`). This exact class of defect (M1) was
   found in PR #81 by adversarial review.
3. **Silent no-op anchor.** A `NullAnchor` must be documented as providing no
   rollback resistance, and the store must record which anchor mode produced a
   committed generation, so modes cannot be mixed.
4. **Authority metadata.** An external witness authenticates the device (mTLS
   client certificate in the reference) and sees per-group timing. That is a
   first-order conflict with Arcium's anonymity goal and is an open product
   decision, not an engineering detail. A peer-assisted anchor leaks nothing the
   peer does not already know and is the better research direction for Arcium.
5. **Publication before durable commit — report it as itself, not as C-01.**
   Returning an artifact before its state transition commits violates the
   ordering above and is a defect on its own evidence. It is **not** the same
   finding as C-01, and citing C-01 as the observed effect is an evidence error.
   C-01 is a reproduced counterexample in MBR v0.1 whose cause is specific:
   rollback past a *committed* send **combined with a constant zero nonce**,
   giving two ciphertexts under one message key and keystream reuse provable by
   XOR. Arcium draws a fresh random 24-byte nonce per message
   (`core-crypto/src/ratchet.rs`, `aead_encrypt`), so the same ordering slip does
   not automatically reproduce that: two encryptions under one message key would
   carry distinct nonces and would not be a two-time pad. What it does produce is
   a protocol-level fork — an artifact exists in the world that the sender's
   durable state does not record, so after a restart the sender can re-derive the
   same chain position and emit a *different* ciphertext there, and a receiver may
   accept two different plaintexts at one logical position. State the boundary
   violation and the fork; mention C-01 only as the related MBR finding, and only
   with its zero-nonce precondition attached.
