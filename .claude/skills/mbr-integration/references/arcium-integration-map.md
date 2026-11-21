# Arcium state per MBR mechanism, and the proposed staging

Two parts, deliberately separated: **where to read** the facts about this
repository (part 1), and a **proposal** whose status is stated stage by stage
(part 2). Do not quote a stage of part 2 in the present tense unless the code,
read where part 1 points, shows it.

Repository layout is not repeated here — see
`engineering-code-review/references/repo-map.md`. This file covers only what
bears on durable state.

## Part 1 — where Arcium's current state is read (category 1)

This file keeps no per-mechanism copy of that state. The table it kept was
checked at `de328a1`; at `d578295`, `git log --oneline de328a1..d578295 --
crates/core-storage crates/core-protocol crates/core-crypto/src/ratchet.rs
crates/mobile-ffi docs/S2-B2-DURABLE-MESSAGING.md docs/NET-MESSAGING.md`
listed 85 commits (77 without merges) that had changed what it described, and
its rows had drifted (the ACK row named two of the ways a
text leaves the outbox; reset, cancel, delete and GONE notices came later).
Read the state from the code and
the specifications at your target SHA. `docs/S2-B2-DURABLE-MESSAGING.md`
("S2-B2 §n") governs the durable layer, `docs/NET-MESSAGING.md` ("NET §n")
the network layer and history; where they and the code disagree, the code
wins.

| MBR mechanism | where to read Arcium's state |
|---|---|
| encrypted storage, single-write atomicity | `crates/core-storage/src/lib.rs`: module doc, `put_row` (F-10) |
| multi-write transaction | `EncryptedStore::transaction` (`BEGIN IMMEDIATE`), `StoreTransaction::commit` / `rollback` |
| durable ratchet state | S2-B2 §1, §3; `core-crypto/src/ratchet/checkpoint.rs`, `core-protocol/src/checkpoint.rs`, `core-protocol/src/durable.rs`, `Messenger` (`core-protocol/src/messaging.rs`) |
| rollback on failed auth | `DoubleRatchet::decrypt` (`core-crypto/src/ratchet.rs`; F-1) |
| duplicate rejection, exact event identity | S2-B2 §2, §6 (`message_id`, `inbox:` and `seen:`); NET §10 for the history |
| skipped-key bounds | `MAX_SKIP`, `max_skipped`, `trim_skipped` and the older-chain memory in `core-crypto/src/ratchet.rs`; tracker R-21, R-23, R-25, H-6 |
| immutable outbox, retry | S2-B2 §5; module doc of `mobile-ffi/src/network.rs` |
| ACK bound to an artifact | NET §5, §6 |
| explicit states, recovery handles | `ChatEntryState`, `ChatSessionState` (`network/chat.rs`); S2-B2 §7 (`recover_session`, `RecoveryReport`) |
| durability settings | `EncryptedStore::init`, pinned by the test `durability_configuration_is_pinned`; S2-B2 §8 |
| persisted records | S2-B2 §2; identity and prekey records (`mobile-ffi/src/identity.rs`, `mobile-ffi/src/prekeys.rs`), contact cards (`mobile-ffi/src/contacts.rs`), history (`network/chat.rs`) |

These are absent, or only assumed, by an owner decision or by design, and
they are the easiest to overstate. Re-check each before relying on it:

- **power-loss durability:** assumed, not demonstrated; it depends on the
  device honouring `fsync` on files and directories (S2-B2 §8);

- **rollback detection:** not provided; owner decision D-009 (S2-B2 §8,
  "Rollback decision");
- **skipped-key age expiry:** not provided (the `skip_age` grep below is
  empty);
- **bounded replay and history retention:** not provided (S2-B2 §8,
  "Retention"; NET §10);
- **Tor / SOCKS on the relay path:** not provided (NET §1, §8; F-15);
- **hardware-backed key provider:** partial; `MasterKeyProvider.kt`
  requests no StrongBox, attestation or user-auth binding (tracker R-18 (b)).

`local_session_handle` is **little-endian** by in-crate convention
(`core-crypto/src/session_handle.rs`) and is local-only; `spk_id` is
big-endian because it goes on the wire (`core-crypto/src/spk_id.rs`). Never
model one on the other.

Commands:

```bash
grep -n "PRAGMA" crates/core-storage/src/lib.rs                # durability set at open
grep -n "pub fn transaction\|pub fn commit\|pub fn rollback" crates/core-storage/src/lib.rs
grep -n "Messenger" crates/mobile-ffi/src/lib.rs               # the app's sessions go through the durable layer
grep -rn "SessionManager" crates/mobile-ffi/src                # empty = no in-memory session map in the app
grep -rn '"[a-z-]*:v1/' crates/*/src                           # versioned record keys
grep -n "const [A-Z_]*KEY: &str" crates/mobile-ffi/src/{identity,prekeys}.rs  # identity and prekey records
grep -n "MAX_SKIP\|max_skipped\|fn trim_skipped\|MAX_PREV_CHAINS" crates/core-crypto/src/ratchet.rs
grep -rni "CommitAnchor\|NullAnchor\|skip_age" crates           # empty = S6 and S7 not started
```

The `:v1/` grep misses keys built from a constant or a helper: `outbox:` and
`inbox:` (`OUTBOX_NAMESPACE`, `INBOX_NAMESPACE` in
`core-protocol/src/messaging/records.rs`) and history entries
(`entry_namespace`, `network/chat.rs`).

## Part 2 — proposed staging (category 3)

Dependency order, not priority. No stage is authorized by this file.

Status as last checked (2026-11-19, `main` @ `d578295`; re-derive from part 1):
**S1** is implemented (transaction API; S2-B2 later set the PRAGMAs
explicitly). **S2** is implemented: S2-B1
(`core-crypto`/`core-protocol`, PR #87) and S2-B2 (PRs #93, #94). **S3** and
**S4** are covered by S2-B2 (outbox, message id, receive committed with its
inbox record; S2-B2 §3, §5, §6). **S5** exists only partly and in a different
shape (the explicit-states row of part 1); it has not been assessed against this
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
