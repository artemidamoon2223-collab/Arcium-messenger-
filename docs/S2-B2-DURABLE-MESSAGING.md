# S2-B2 — Durable messaging lifecycle

Specification for the durable messaging subsystem built on S1 (transactional
encrypted storage, `core-storage`) and S2-B1 (`DurableSession`,
`core-protocol/src/durable.rs`). It states what the implementation must hold,
where each state transition happens, and what each piece of evidence shows.

Cryptography is unchanged: X3DH, the Double Ratchet, XChaCha20-Poly1305, KDF
contexts, nonce generation and every on-wire structure are the same as before.
Only local persistence and the order of local operations change.

## 1. Authority

- Rust (`core-protocol::messaging`, called from `mobile-ffi`) is the only code
  that loads, advances or writes a session. Kotlin receives public values
  (message ids, ciphertext it must send, plaintext it must show) and status.
- There is no long-lived in-memory ratchet. Every operation loads the session
  from the store, stages the transition on a copy, and commits it with a
  conditional write whose precondition is "the stored record is exactly the
  generation this operation loaded". Two `ArciumCore` instances, two threads or
  two processes on one database therefore cannot both advance from one
  generation: the second commit is a `Conflict`, writes nothing and releases
  nothing.
- The store holds the only copy of the state. A process that dies loses nothing
  that was committed and nothing that was released.

## 2. Persistent data model

All records live in the S1 `EncryptedStore` (values and key names encrypted,
see `core-storage`). New record types are versioned and fixed-layout; nothing
here is transmitted.

| key | record | written by |
|---|---|---|
| `session:v1/<peer>` | `SESSION_CHECKPOINT_V1` (unchanged, S2-B1) | every transition |
| `handle:v1/<handle>` | `HANDLE_RECORD_V1`: peer identity key the local handle belongs to | session creation |
| `hsout:v1/<peer>` | initiator handshake bytes (public) | initiator session creation |
| `outbox:v1/<peer>/<id>` | `OUTBOX_RECORD_V1`: generation, message id, client message id, exact wire bytes; only while unacknowledged | send |
| `sendid:v1/<peer>/<client id>` | `SENDID_RECORD_V1`: the message id a logical message produced, sent or abandoned | send, abandon outgoing |
| `inbox:v1/<peer>/<id>` | `INBOX_RECORD_V1`: generation, message id, plaintext; only while undelivered | receive |
| `seen:v1/<peer>/<id>` | `SEEN_RECORD_V1`: id of an acknowledged incoming message | acknowledge incoming |
| `prekeys/v2` | unchanged format | responder session creation (same transaction) |

`<peer>` is the peer's X25519 identity key in hex, `<handle>` the local `u64`
handle in hex, `<id>` a message id in hex, `<client id>` the caller's logical
message id in hex.

Only `outbox:` and `inbox:` are ever listed, and they hold pending entries
only. What is kept after an acknowledgement (`sendid:`, `seen:`) is read by
exact key, so listing pending messages does not get slower as history grows.

**Message id** = `SHA-256("ARCIUM-MESSAGE-ID-V1" || wire)`, where `wire` is the
exact `header || ciphertext` bytes. Both peers compute the same id from the same
bytes without it being transmitted, so an acknowledgement or a duplicate check
names one exact artifact. It is an identifier, not a MAC.

## 3. Transaction boundaries

Every state change is one S1 transaction (`BEGIN IMMEDIATE` … `COMMIT`) made
of conditional writes. Each write carries a precondition checked inside the
transaction; if any precondition fails, nothing is written.

| operation | writes in one transaction | preconditions |
|---|---|---|
| initiator establishment | session gen 0, handle, handshake | session absent, handle absent |
| responder establishment | session gen 0, handle, rotated prekey record | session absent, handle absent, prekey record byte-identical to the one validated |
| send | session gen n+1, outbox record, send-id record | session is the record loaded (gen n, same SHA-256), outbox id absent, send-id absent |
| receive | session gen n+1, inbox record (undelivered) | session is the record loaded, inbox id absent, seen id absent |
| acknowledge incoming | inbox record deleted, seen record written | inbox record present, else no-op (idempotent) |
| acknowledge outgoing | outbox record deleted (send-id kept) | outbox record present, else no-op (idempotent) |
| abandon outgoing | outbox record deleted, send-id marked abandoned | outbox record present, else no-op (idempotent) |
| remove session | session, handle, handshake deleted | see 6a; session record unchanged since checked |

A transition's precondition names the exact record it was staged from, not
only its generation. A session that is removed and created again with the same
peer starts at generation 0 again; without the digest, a transition staged from
the old session commits over the new one and destroys it (reproduced on
`bf4ea51`: the new session's peer could no longer decrypt). It is now refused
as `Conflict::Superseded`.

An error from the `COMMIT` of an acknowledgement, an abandonment or a removal
is reported as `RepeatableOutcomeUnknown`, never as a rollback: repeating the
call reports what the store holds.

Order of every transition:

```
load(gen n) → stage on a copy → encode records → BEGIN → check preconditions
  → write all → COMMIT → only now return the ciphertext / plaintext / handshake
```

No output of a transition leaves Rust before its `COMMIT` returned `Ok`.

## 4. Session establishment

- **Initiator.** X3DH, then one transaction storing the session, the handle and
  the handshake. The handshake is returned only after commit and can be read
  again later (`Messenger::initial_outbound`; `initiator_handshake` over the
  FFI) if the process dies before sending it.
- **Responder.** The prekey record is read and validated against the handshake
  (unchanged rules), X3DH runs, then one transaction stores the session and the
  handle and replaces the prekey record with the rotated one — only if the
  prekey record is still byte-identical to what was validated. A crash before
  `COMMIT` leaves the one-time prekey unconsumed and no session; the same
  handshake can be answered again. A crash after `COMMIT` leaves both.
  A concurrent consumer changes the record and turns the precondition into
  `OneTimePrekeyUnavailable`.
- **Refused establishment.** If the session or handle already exists (valid or
  not), nothing in that transaction is written. The one-time prekey the
  handshake named is then consumed in a separate transaction, as before
  (a handshake that reached the responder never returns its prekey to
  circulation). If that second write fails, the refusal is still reported.
- An existing record that cannot be decoded, has another binding or another
  role is an explicit error. It is never replaced by a new session.

## 5. Outgoing messages

- `send_message(client_message_id, plaintext)` takes the caller's own id for
  the logical message (1–64 bytes, unique per logical message). The first call
  commits the new checkpoint, the outbox record and the send-id record together
  and returns `Sent{message_id, wire}` only after commit. Every later call with
  the same id encrypts nothing: it returns `AlreadyPending` with the stored
  bytes, or `AlreadyAcknowledged`. A caller that cannot tell whether a send
  took effect — an unknown commit outcome, a crash, a restart — calls again
  with the same id. Without this, a repeated send was a second ciphertext of
  the same logical message, and the peer accepted it twice (reproduced on the
  first version of this PR).
- `pending_outgoing` returns every committed, unacknowledged outgoing message in
  generation order, with the stored bytes. Retransmission sends these bytes; it
  never encrypts again, and never advances the ratchet.
- `acknowledge_outgoing(message_id)` removes the record once transport confirms
  delivery. Repeating it is harmless. (There is no transport or peer ACK yet;
  this is the hook it will call.)
- `abandon_outgoing(message_id)` is the caller's explicit decision to stop
  retransmitting a message without a delivery confirmation. The outbox record
  goes, and the logical id is marked abandoned in the same transaction:
  `send_message` with that id returns `Abandoned` and encrypts nothing, so the
  outcome survives a crash and the content is only sent again under a new id,
  deliberately. Abandoning claims nothing about the peer, which may or may not
  have the message. An acknowledgement and an abandonment of the same message
  are serialized; exactly one of them reports it as pending.

## 6. Incoming messages

- `receive_message(wire)` computes the id first. If an inbox record for that id
  exists, the ratchet is not touched and the result is `duplicate`
  (with the plaintext again if it is still undelivered).
- Otherwise the decryption is staged, and the checkpoint and an undelivered
  inbox record are committed together. The plaintext is returned only after
  commit.
- `pending_incoming` returns committed, undelivered messages in generation order.
- `acknowledge_incoming(message_id)` deletes the inbox record (and its
  plaintext) and keeps the id in `seen:` for duplicate detection. Repeating it
  is harmless. Acknowledgement means **the application has durably processed
  the message**; acknowledging earlier can lose it.
- Delivery to the application is **at least once**, not exactly once: a
  message the application showed but did not acknowledge before a crash is
  pending again after restart. The `message_id` identifies such a repeat, and
  the application must treat it idempotently.

The stages are distinct: *accepted* by the ratchet and *persisted* for the
application happen in one commit; *returned* through the FFI happens after
that commit; *shown or processed* by Android is outside Rust; *acknowledged*
is the application's explicit `acknowledge_incoming`.

## 6a. Removing a session

`remove_session(handle)` is the way out of a session whose handshake the peer
refused: a peer has at most one session, so without it such a session could
never be replaced (reproduced on the first version). What it may do follows
from what the local store can and cannot know.

The store cannot tell a refused handshake from one whose delivery is unknown:
there is no authenticated refusal, and a missing acknowledgement proves
nothing. It *can* tell whether the session has committed a message from the
peer (the ratchet has a receiving chain only after an authenticated decrypt).
If it has, the peer holds the session too, and removing it locally would
leave the peer with a history this side no longer has.

| state | removal | why |
|---|---|---|
| commit with unknown outcome on this handle | refused, `Unresolved` | an ambiguous commit is not a rollback; `recover_session` first |
| session record unreadable or missing | refused, `InvalidSession` / `MissingSession` | whether it holds obligations cannot be decided |
| a message from the peer committed (established) | refused, `SessionEstablished` | the peer holds the session; resetting it needs a peer-authenticated protocol, which does not exist here |
| outgoing messages neither acknowledged nor abandoned | refused, `PendingOutgoing{count}` | each may have been published; the caller settles them one by one |
| no message received, nothing pending (handshake refused or its delivery unknown) | session, handle and stored handshake deleted in one transaction | nothing received, nothing owed |
| a send or receive commits between the checks and the transaction | refused, `Conflict(RecordChanged)`, nothing deleted | only those add obligations, and they change the record |

Undelivered incoming messages imply a committed receive, so they are covered by
`SessionEstablished`. `seen:` and `sendid:` records survive removal: a message
already seen is still a duplicate, and a logical id keeps its outcome
(`AlreadyAcknowledged`, `Abandoned`) for every later session with that peer, so
nothing is encrypted twice for one logical id. A new session inherits no
pending message: removal requires that there is none.

Replacing a handshake whose delivery was unknown forks nothing: a peer that did
accept it keeps its session and refuses the new handshake (`AlreadyExists`),
and messages of either session fail to decrypt under the other and write
nothing. What that costs is liveness: those two peers stay unable to talk until
the peer's session can be reset, which needs a peer-authenticated reset
protocol that is out of scope. Local removal proves nothing about the peer.

- A forged or undecryptable message stages nothing and writes nothing.

## 7. Failure and recovery

| event | stored state | released | next step |
|---|---|---|---|
| failure before `BEGIN` / during staging | unchanged | nothing | error; retry is safe |
| precondition failed | unchanged | nothing | `Conflict`; next call reloads |
| failure before `COMMIT` (`NotCommitted`) | unchanged | nothing | error; retry is safe |
| `COMMIT` returned an error | unknown | nothing | session is **unresolved**: every transition on it is refused until `recover_session` |
| process dies before `COMMIT` | unchanged (SQLite journal) | nothing | reload |
| process dies after `COMMIT`, before return | new generation + record | nothing yet | outbox / inbox holds the artifact; resend from outbox, deliver from inbox |
| process dies after return, before publication / delivery | same | caller had it | same as above, same bytes |
| same ciphertext received again | unchanged | no new plaintext | `duplicate` |
| two instances stage from one generation | first commit wins | only the winner's output | loser gets `Conflict` |
| transition staged from a session since removed and re-created | the new session, untouched | nothing | `Conflict::Superseded` |
| corrupt / incompatible checkpoint | unchanged | nothing | explicit error; never replaced |
| SQLite left a transaction open | unchanged | nothing | S1 refuses (`TransactionStateInvalid`) |

**Unresolved commit.** An error from `COMMIT` is never read as a rollback. The
output of that transition was withheld, so whatever the store holds, nothing
competing with it was released. `recover_session` reads the stored generation
and whether the artifact's record exists, reports which, and clears the flag.
Continuing from the stored state is then safe *with respect to what was
released*. Reading the store says nothing about power loss or a database file
replaced by an older copy. The flag lives in memory; a restart reaches the same
point by loading from the store.

## 8. Storage durability

Configuration, set explicitly at open (`core-storage`):

- `journal_mode = DELETE` (unchanged). S1's contention analysis and tests rely
  on rollback-journal semantics.
- `synchronous = EXTRA` (was the default `FULL`). In rollback-journal mode
  `FULL` does not sync the directory after deleting the journal, so the last
  committed transaction can come back as a hot journal after a power cut and be
  rolled back. `EXTRA` adds that sync. Losing a commit whose ciphertext was
  already sent would let the sender re-derive the same chain position and emit a
  different ciphertext there — a protocol fork — so durability of released
  commits is required, not optional.

What is and is not established:

| property | status |
|---|---|
| atomicity of each transition | S1 transaction; tested |
| successful `COMMIT` visible to all connections | tested |
| process-crash recovery (before/after `COMMIT`) | real process aborts in tests |
| power-loss durability | **assumed**: requires the device to honour `fsync` on file and directory; not demonstrated. The bundled SQLite is built without `SQLITE_DISABLE_DIRSYNC` for every target, Android included (`libsqlite3-sys` 0.28 `build.rs`) |
| malicious rollback (older database file) | **not provided**; needs an external authority, not in scope |

A restored older database file brings back an older checkpoint *and* its
generation together, so the generation counter cannot detect it. The sender
can then re-derive a chain position it already used and emit a different
ciphertext there (a fork); the receiver rejects the second one only if it
already consumed that position. Nothing here prevents that.

Retention: `seen:` and `sendid:` records are kept for the life of the session
and beyond, including across its removal (about 40 bytes of payload plus the store's per-row overhead per
message). They are never listed, so they cost disk space, not time.

## 9. Compatibility

`SESSION_CHECKPOINT_V1`, `RATCHET_STATE_V1`, `PREKEY_BUNDLE_V1`,
`INITIATOR_HANDSHAKE_V1`, `PERSISTED_PREKEY_RECORD_V2` and the message format
`header(40) || ciphertext` are unchanged. The FFI messaging calls change shape
(`send_message` takes a client message id and returns an outcome;
`receive_message` returns a record) and `remove_session` and `abandon_outgoing` are new; the bytes on
the wire are identical.

## 10. Verification plan

| property | test | evidence class |
|---|---|---|
| one commit ↔ one installed successor; output only after commit | core-protocol unit tests over S1 | runtime |
| outbox bytes identical across retries and restarts | core-protocol + mobile-ffi | runtime |
| duplicate ciphertext: no second acceptance, no ratchet step | core-protocol + mobile-ffi | runtime |
| stale / competing instances cannot both publish | two connections, two threads, two `ArciumCore` | runtime |
| responder prekey + session atomic | conditional batch; process abort before/after commit | process crash |
| crash before / after `COMMIT`, before publication, before delivery | child process `abort()` at each point | process crash |
| ambiguous `COMMIT` → unresolved, nothing released | scripted store failures | simulated |
| invalid checkpoint never overwritten | corrupt record + create / receive / remove | runtime |
| removal refused while unresolved, established or with pending outgoing; abandonment explicit and durable | `messaging/tests/lifecycle.rs` | runtime; unknown outcomes simulated |
| a stale transition never commits over a replacement session | race hook on a second connection | runtime |
| a logical message is never accepted under two sessions | two peers, replacement refused by the peer | runtime |
| process death before / after the removal's `COMMIT` | child process `abort()` | process crash |
| wire format unchanged | old-format decrypt across new API; fixed lengths | runtime |
| Android: establish, messaging, process kill, restart, restore, pending recovery | instrumentation tests on an emulator, victim process killed with `Process.killProcess` | Android runtime (emulator) |
| power loss | — | not verified |
