# Arcium state per MBR mechanism, and the proposed staging

Two parts, deliberately separated: **verified facts** about this repository, and
a **proposal that is not implemented**. Do not quote part 2 in the present tense.

Repository layout is not repeated here — see
`engineering-code-review/references/repo-map.md`. This file covers only what
bears on durable state.

## Re-derive before relying on any of this

Facts below were verified at `99c9f49`. They drift. Commands:

```bash
git rev-parse HEAD                                            # is this still 99c9f49?
grep -n "pub fn " crates/core-storage/src/lib.rs              # does a transaction API exist yet?
grep -rn "BEGIN\|COMMIT\|\.transaction()" crates/*/src/*.rs   # empty = still no multi-write txn
grep -n "const [A-Z_]*KEY: &str" crates/mobile-ffi/src/lib.rs # what is actually persisted
grep -n "serialize\|persist\|save\|load" crates/core-protocol/src/lib.rs
grep -n "MAX_SKIP\|max_skipped\|trim_skipped" crates/core-crypto/src/ratchet.rs
```

## Part 1 — verified state (category 1)

| MBR mechanism | Arcium status | evidence at `99c9f49` |
|---|---|---|
| encrypted storage | **ALREADY** | XChaCha20-Poly1305 over values *and* key names, `core-storage/src/lib.rs:181-230` |
| single-write atomicity | **ALREADY** | `put` is one `conn.execute`, `core-storage/src/lib.rs:76-86` |
| **multi-write transaction** | **NOT** | 6 public methods only; `BEGIN`/`COMMIT`/`transaction()` appear in no crate |
| durable ratchet state | **NOT** | `core-protocol/src/lib.rs` (224 lines) has no serialize/save/load; sessions are a `HashMap` in memory |
| rollback on failed auth | **ALREADY** | snapshot/rollback, `core-crypto/src/ratchet.rs:149-172` (finding F-1) |
| duplicate rejection | **PARTIAL** | ratchet level only — `swap_remove`, `ratchet.rs:182`. No application-level dedup |
| skipped-key capacity bound | **PARTIAL** | `MAX_SKIP = 1000` (`ratchet.rs:27`), `max_skipped = 2000` (`:107,124`), `trim_skipped` zeroizes (`:292-297`) |
| skipped-key **age** expiry | **NOT** | no logical-time expiry; MBR uses `SKIP_AGE = 128` receives |
| immutable outbox / retry | **NOT** | `encrypt_message` (`mobile-ffi/src/lib.rs:767`) mutates and returns; a resend re-encrypts |
| exact event identity | **NOT** | messages carry only the ratchet header |
| ACK bound to an artifact | **NOT** | no ACK; deliberately deferred by owner decision D5 |
| rollback detection | **NOT** | nothing compares durable state to anything external |
| bounded replay/history retention | **NOT** | no history log exists |
| PENDING/READY/BLOCKED/RETIRED | **NOT** | no such enum in Rust or Kotlin |
| hardware-backed key provider | **PARTIAL** | `MasterKeyProvider.kt:77-84` requests only `PURPOSE_ENCRYPT|DECRYPT` + GCM — no StrongBox, no attestation, no user-auth binding. Non-exportable, unverified security level |
| SOCKS "no direct fallback" rule | **UNKNOWN** | no transport exists: `core-transport` is 101 lines, `onion_address` is the literal `"TODO.onion"` (`:30`), `_state_dir` ignored (`:23`) |

Persisted keys, in full: `identity/v1` (`mobile-ffi/src/lib.rs:168`) and
`prekeys/v2` (`:174`). Nothing else survives process death.

Durability PRAGMAs are SQLite defaults — only `secure_delete = ON` is set
(`core-storage/src/lib.rs:66`).

`local_session_handle` is **little-endian** by in-crate convention
(`core-crypto/src/session_handle.rs:61`) and is local-only; `spk_id` is
big-endian because it goes on the wire. Never model one on the other.

## Part 2 — proposed staging (category 3 — NOT IMPLEMENTED)

Dependency order, not priority. No stage is authorized by this file.

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

## Known risks to check in any MBR-shaped diff

1. **Two authorities.** Does Kotlin gain state, or a callback inside the commit
   boundary? Both are refusals.
2. **Un-zeroized secrets.** Serializing ratchet state puts the root key and
   chain keys in a byte buffer. Without `Zeroizing` that is a regression against
   `ratchet.rs:305`. This exact class of defect (M1) was found in PR #81 by
   adversarial review.
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
