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
| `hsin:v1/<handle>` | `PROVISIONAL_HANDSHAKE_RECORD_V1`: peer identity key and the handshake a responder received (public), not yet authenticated | responder: handshake receipt; deleted by the first authenticated message. Also beside this device's own unconfirmed initiator session (section 4c); deleted when that session is confirmed, removed or forgotten |
| `outbox:v1/<peer>/<id>` | `OUTBOX_RECORD_V1`: generation, message id, client message id, exact wire bytes; only while unacknowledged | send |
| `sendid:v1/<peer>/<client id>` | `SENDID_RECORD_V1`: the message id a logical message produced, sent or abandoned | send, abandon outgoing |
| `inbox:v1/<peer>/<id>` | `INBOX_RECORD_V1`: generation, message id, plaintext; only while undelivered | receive |
| `seen:v1/<peer>/<id>` | `SEEN_RECORD_V1`: id of an acknowledged incoming message | acknowledge incoming |
| `prekeys/v2` | unchanged format | responder session creation from the first authenticated message (same transaction) |

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
| responder: handshake received | provisional handshake record only | handle absent, session absent (read in the same transaction) |
| responder: first message authenticated | session gen 1, handle, inbox record (undelivered), rotated prekey record, provisional record deleted | session absent, handle absent, provisional record byte-identical to the one the session was derived from, inbox id absent, seen id absent, prekey record byte-identical to the one validated |
| handshake beside own session (4c) | provisional record only | session record byte-identical (SHA-256) to the one classified as this device's own initiator session with nothing received, handle record naming the peer (read in the same transaction) |
| send | session gen n+1, outbox record, send-id record | session is the record loaded (gen n, same SHA-256), outbox id absent, send-id absent |
| receive | session gen n+1, inbox record (undelivered), the peer's provisional record beside the session deleted (4c) | session is the record loaded, inbox id absent, seen id absent, that provisional record exactly the one read (or still absent if none was) |
| acknowledge incoming | inbox record deleted, seen record written | inbox record present, else no-op (idempotent) |
| acknowledge outgoing | outbox record deleted (send-id kept) | outbox record present, else no-op (idempotent) |
| abandon outgoing | outbox record deleted, send-id marked abandoned | outbox record present, else no-op (idempotent) |
| remove session | session, handle, handshake, the peer's provisional record beside it (4c) deleted | see 6a; session record unchanged since checked |

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
- **Responder.** A received handshake is not authentication: its bytes are
  public and anyone can send them. So receiving one never creates a session.
  The handshake is validated against the prekey record (unchanged rules) and
  stored as a *provisional* record under the handle — nothing else: no
  session, no handle, no consumed prekey. It has no authority. `has_session`
  is false, nothing can be sent or removed on it, and a later handshake for the
  handle replaces it. It is refused, with nothing written, once a session with
  that peer exists or the handle belongs to another peer. (One exception, in
  the network layer only: beside this device's own unconfirmed initiator
  session it is recorded under the same rules, section 4c.)
- **Promotion.** The session is created by the initiator's first message, and
  only if it authenticates. X3DH runs again from the provisional handshake
  against the prekeys held now (checked again), and the message is decrypted
  on that result held in memory (`durable::ProvisionalSession`, which cannot
  encrypt and is never stored). Only if the AEAD verifies — which requires the
  keys X3DH derived, and so the initiator's identity secret — does one
  transaction store the advanced session at generation 1 (it already has its
  receiving chain), its handle, the message as an undelivered inbox record,
  the prekey record rotated past the one-time prekey, and delete the
  provisional record. Preconditions: no session record for the peer, the
  handle free, the provisional record exactly the one used, the message never
  accepted, the prekey record byte-identical to what was validated. The
  plaintext is returned only after that commit.
- **Promotion happens once.** A second attempt finds the session record and
  receives the message on that session instead: the same message is a
  duplicate. A message that does not authenticate writes nothing and leaves
  the provisional record as it is.
- **Crash boundaries.** Dying after the handshake was recorded leaves the
  provisional record: after a restart it is still not a session, and its first
  message still creates one. Dying inside the promotion's transaction leaves
  all of it or none of it. An unknown `COMMIT` outcome makes the handle
  unresolved like an unknown creation; `recover_session` reports whether the
  session exists.
- **One-time prekeys** are consumed only by the promotion's transaction, never
  by an unauthenticated handshake. A one-time prekey contributes to at most one
  session: two provisional handshakes naming it cannot both be promoted,
  because the promotion requires the prekey record it validated to be
  unchanged. Until a promotion consumes it, the one-time prekey stays
  published, exactly as before any handshake arrived.
- **Refused handshakes** (a session exists, or the handle belongs to another
  peer) write nothing and consume nothing.
- An existing record that cannot be decoded, has another binding or another
  role is an explicit error. It is never replaced by a new session.

## 4b. Responder sessions stored by earlier builds

Builds up to `590c936e` stored a responder session on receipt of a handshake:
`session:v1/<peer>` at generation 0 with the ratchet exactly as `init_bob`
creates it, and `handle:v1/<handle>`; the one-time prekey was consumed. Until
a message from the peer authenticated under it, such a session carried no
authenticated evidence and could not encrypt (`NotInitialized`), yet it held
the peer's slot: later handshakes from the peer were refused.

- **Classifier** (`DurableSession::is_legacy_unconfirmed`): the record decodes
  for the expected identities, role responder, generation 0, and the ratchet
  is in its initial responder state
  (`DoubleRatchet::is_initial_responder_state`: no `dhr`, no sending or
  receiving chain, `ns = nr = pn = 0`, no skipped keys). A record that does
  not decode is never eligible. Current code never stores this shape on the
  production path (responder sessions are stored at generation 1).
- **Retirement.** `record_provisional_handshake` for the same peer under the
  same handle retires such a session: one S1 transaction deletes the session
  and handle records and records the new handshake as provisional. From then
  on section 4 applies unchanged. The transaction requires: the session record
  byte-identical (SHA-256) to the one classified, the handle record still
  naming the peer, no `hsout` and no `hsin` record, and the prekey record still
  exactly the one the new handshake passed the prekey rules against. Before
  it, no outbox or inbox record may exist for the peer; these can only be
  added by a transition of the session record itself (`send`, `receive`), so
  the record check covers them at commit. Nothing is retired while this
  instance has an unresolved commit on the handle.
- **Untouched:** `prekeys/v2` (the one-time prekey the old session consumed
  stays consumed; the new handshake's is consumed by its promotion, as in
  section 4), `seen:`, `sendid:`, chat history and every other peer.
- **Never retired:** a session that authenticated a message from the peer, an
  initiator session, anything at another generation or in another ratchet
  shape, anything with pending messages or a stored handshake beside it, an
  unreadable record. The handshake is then refused as in section 4.
- **Unknown outcome** of the retirement: repeating the call completes it or
  finds it complete. Process death before `COMMIT` leaves the old session;
  after it, exactly the new provisional record.
- **Competing instances.** A receive committed on the old session by another
  instance changes its record, so a retirement classified before it fails
  (`Conflict`). A receive staged on the old session before a retirement
  commits fails its predecessor check and releases nothing.
- **Liveness.** Anyone able to deliver a handshake that passes the prekey rules
  can retire such a session, exactly as they can replace a provisional record;
  the session had no more authority than one. If the old handshake's own first
  message arrives before any retirement, it authenticates on the old session,
  which then continues as an ordinary session. If a retirement comes first,
  that old handshake cannot be answered again — its one-time prekey was
  consumed by the earlier build and is never restored — so its initiator's
  session stays unconfirmed until one side starts a new one (for example
  through the conflict resolution of `NET-MESSAGING.md` section 10). Unlike a
  replaced provisional record, which the genuine handshake's retransmission
  restores, this is not undone by retransmission.

## 4c. A handshake beside this device's own unconfirmed session

When both devices start a session with each other, each receives the other's
handshake while it holds an initiator session of its own on which nothing
from the peer has been received. Until tracker R-13 was addressed (option A
of `docs/SESSION-RECOVERY-OPTIONS.md`), the network layer dropped that
handshake and recorded a session conflict on it alone. A handshake is public
bytes, so anyone who reaches the relay could raise a false conflict, and
resolving one dead-ended the conversation (R-13). Section 4 did not allow a
provisional record beside a session. This section changes that.

- **Recording.** `Messenger::record_handshake_beside` stores the handshake as
  a provisional record (`hsin:v1/<handle>`, the same key and format as
  section 4), next to the session, after its caller
  (`ArciumCore::record_handshake_beside` in `mobile-ffi`) checked it against
  the prekey record by the rules of section 4. One transaction reads
  the handle record (it must name the handshake's peer) and the session
  record, which must be byte-identical (SHA-256) to the one classified before
  it as this device's own initiator session with nothing received from the
  peer, and writes the record. Refused, with nothing written: no session
  (`NoSession`), the handle belongs to another peer (`HandleCollision`), any
  other session (a responder session, one that has received from the peer,
  an unreadable one: `AlreadyExists`), an unresolved commit on the handle
  (`Unresolved`), and a session or handle record changed since it was read
  (`Conflict`). The same handshake again changes nothing; another replaces
  it. Nothing is consumed, the session record is not touched, and nothing
  else is derived from the record: it has no more authority than any
  provisional record.
- **Use.** While the session exists it is used for one thing only: when a message
  from the peer fails to decrypt under the session,
  `Messenger::first_message_authenticates` checks whether it authenticates
  as the peer's first message under the recorded handshake. The caller runs
  X3DH from the handshake against the prekeys held now, checked again by the
  rules of section 4, with the one-time prekey only read, never taken; the
  message is decrypted on that result in memory
  (`durable::ProvisionalSession`, never stored). The AEAD verifies only under
  keys derived with the secret of the identity key the handshake names, so a
  `true` is evidence the peer made the message. Nothing is written, nothing
  consumed, and the session is not advanced, replaced or removed. What the
  network layer does with the answer is `docs/NET-MESSAGING.md` section 10
  ("Conflict").
- **No promotion.** A recorded handshake never becomes a session while this
  device's session with the peer exists: `receive` finds that session and
  decrypts on it, and a promotion requires that no session record exists
  (section 4).
- **Discarded with the session's fate.**
  - Confirmed: a `receive` that commits a message from the peer on the
    session deletes the record in the same transaction (precondition: the
    record exactly as read, or still absent if none was). Another
    connection recording one between the read and the commit makes the
    receive fail with `Conflict` and nothing written; repeating it deletes
    the record.
  - Removed: `remove_session` deletes it with the session, handle and stored
    handshake (section 6a). The peer retransmits its handshake while its
    own session is unconfirmed, and it is then recorded as for any first
    contact. Keeping the record, as a responder's provisional record, would
    save no round: the peer sends its handshake and first message together,
    and a round processes handshakes first.
  - Forgotten: `forget_peer` already deletes the provisional record under the
    handle (section 6a).
  - A record naming another peer under a colliding handle is not this
    peer's: none of these touch it, and the check above ignores it.
- **Crash boundaries.** Dying before the recording's `COMMIT` leaves nothing
  recorded; after it, exactly the record. Dying inside the confirming
  receive leaves the message committed and the record gone, or neither.
  The removal is one transaction as before.
- **Stores written before this change.**
  - A provisional record next to an unconfirmed initiator session can exist:
    a responder recorded a peer's handshake, its first message did not arrive,
    and the device then started its own session (section 4 never forbade
    `create_session` beside a provisional record). It is read as a record
    beside the session, as recorded now. That is what it is: the peer's
    handshake, checked against the prekeys when it was recorded.
  - A provisional record next to an established session can exist (earlier
    builds deleted it only by a promotion). It is never read there: the
    check above runs only for an unconfirmed session of this device's own.
    The next message from the peer committed on the session deletes it.
  - Nothing is rewritten in place, and no record format changes. The
    conflict flag of the network layer changes meaning
    (`docs/NET-MESSAGING.md` section 10).
- **Replay.** A recorded genuine handshake and first message replayed later
  still authenticate if this device can still answer that handshake: its
  one-time prekey is still the published one and its signed prekey current.
  A handshake that created a session here cannot be replayed this way (its
  one-time prekey was consumed and replaced, section 4; the form without a
  one-time prekey has no such protection, tracker X-6, and no production
  path produces one). One this device never accepted can, for as long as no
  other first contact consumes that prekey. The consequence is in
  `docs/NET-MESSAGING.md` section 8.

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
  this is the hook it will call.) Since the network layer: it calls this on
  the peer's receipt, and the call is not exported through UniFFI
  (`docs/NET-MESSAGING.md`, section 5).
- `abandon_outgoing(message_id)` is the caller's explicit decision to stop
  retransmitting a message without a delivery confirmation. The outbox record
  goes, and the logical id is marked abandoned in the same transaction:
  `send_message` with that id returns `Abandoned` and encrypts nothing, so the
  outcome survives a crash and the content is only sent again under a new id,
  deliberately. Abandoning claims nothing about the peer, which may or may not
  have the message. An acknowledgement and an abandonment of the same message
  are serialized; exactly one of them reports it as pending. Not exported
  through UniFFI either: only the network layer's `resolve_session_conflict`
  calls it, after marking the texts not delivered; a text committed after
  that marking is shown not delivered from its abandoned send record
  (`docs/NET-MESSAGING.md`, section 5).

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
| no message received, nothing pending (handshake refused or its delivery unknown) | session, handle, stored handshake and the peer's handshake recorded beside it (section 4c) deleted in one transaction | nothing received, nothing owed |
| a send or receive commits between the checks and the transaction | refused, `Conflict(RecordChanged)`, nothing deleted | only those add obligations, and they change the record |

Undelivered incoming messages imply a committed receive, so they are covered by
`SessionEstablished`. `seen:` and `sendid:` records survive removal: a message
already seen is still a duplicate, and a logical id keeps its outcome
(`AlreadyAcknowledged`, `Abandoned`) for every later session with that peer, so
nothing is encrypted twice for one logical id. A new session inherits no
pending message: removal requires that there is none.

Replacing a handshake whose delivery was unknown forks nothing. A peer that
created its session from it (a message of that session authenticated there)
keeps that session and refuses the new handshake (`AlreadyExists`), and
messages of either session fail to decrypt under the other and write nothing.
A peer that had only recorded it takes the new handshake in its place: a
provisional record has no authority to keep. What that costs is liveness: those two peers stay unable to talk until
the peer's session can be reset, which needs a peer-authenticated reset
protocol that is out of scope. Local removal proves nothing about the peer.

- A forged or undecryptable message stages nothing and writes nothing.

### Forgetting a peer (delete contact)

`forget_peer(handle, peer, also_delete)` is the user's explicit decision to
delete a contact (`delete_contact`, `docs/NET-MESSAGING.md` section 10).
Unlike `remove_session` it does not ask whether obligations remain: it is
the way out of a session that can no longer progress (option C of
`docs/SESSION-RECOVERY-OPTIONS.md`). It is the one exception to "an
established session is not removed" above and to "never replaced by a new
session" for an unreadable record (section 4). The rules of
`remove_session` are unchanged.

- One transaction deletes, whatever state the session is in (established,
  unconfirmed, unreadable or absent): the session record, the handle record
  (also an unreadable one), the stored initiator handshake, the provisional
  handshake under the handle (unless it names another peer), every
  `outbox:` and `inbox:` record of the peer, and the caller's own records
  for the peer (`also_delete`).
- In the same transaction, each pending outgoing message's `sendid:` record
  is rewritten as abandoned, as `abandon_outgoing` does. `send` and
  `prior_send` then report `Abandoned`, never `AlreadyAcknowledged`: only a
  receipt acknowledges. For an outbox record that cannot be decoded, the
  message id is taken from its key, and every `sendid:` record of the peer
  naming that id is rewritten as abandoned in the same transaction.
- Each deleted `inbox:` record leaves a `seen:` record for its id (from its
  key), in the same transaction: the message, never shown, is a duplicate
  if it ever arrives again rather than new.
- `seen:` and `sendid:` records stay, as after a removal: a message already
  seen is still a duplicate under a later session, and no logical id is
  encrypted twice.
- It discards obligations. Undelivered texts are never sent again, and
  incoming messages the application has not acknowledged are gone.
- The peer is told nothing and keeps its session. It refuses a new
  handshake from this identity (`AlreadyExists`) until it forgets this peer
  too; after both have, the next text starts a new session.
- A transaction cannot list keys, so the `outbox:` and `inbox:` records are
  listed before `BEGIN`. A send or receive another connection commits in
  between is removed in a second transaction, after a fresh listing. If
  records are still found after that, the call fails with
  `Conflict(RecordChanged)` and is repeated.
- An error from its `COMMIT` is `RepeatableOutcomeUnknown`: repeating the
  call reports what the store holds.

| state | forgetting | why |
|---|---|---|
| commit with unknown outcome on this handle | refused, `Unresolved`, nothing changed | an ambiguous commit is not a rollback; `recover_session` first (`delete_contact` does) |
| handle registered to another peer | refused, `HandleCollision`, nothing changed | the records under it are not this peer's |
| anything else: established, unconfirmed, unreadable or missing records, nothing stored | everything listed above deleted in one transaction | the user's explicit decision |

Tests: `messaging/tests/lifecycle.rs` (`forgetting_*`,
`an_unknown_forget_outcome_is_resolved_by_repeating_it`) and
`messaging/tests/crash.rs`
(`process_killed_around_forgetting_a_peer_leaves_it_whole_or_gone`).

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

One case of a missing session is recovered: a receive staged on a session of
section 4b whose outcome is unknown, after another instance retired that
session. `recover_session` clears it only if one read shows no session record,
no handle record, a provisional record from the same peer under the handle,
and neither the inbox nor the seen record of the unknown receive (had it
committed, the session would have a receiving chain and could not have been
retired). Otherwise the handle stays unresolved; a missing session alone is
never read as a rollback.

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
| malicious rollback of a single record (an older row of the same key written back) | **not provided**; decided out of scope for v1, see "Rollback decision" below |

A restored older database file brings back an older checkpoint *and* its
generation together, so the generation counter cannot detect it. The sender
can then re-derive a chain position it already used and emit a different
ciphertext there (a fork); the receiver rejects the second one only if it
already consumed that position. Nothing here prevents that.

### Rollback decision (D-009, 2026-11-08)

**Decision (Owner):** v1 resists neither whole-file nor single-record
rollback. An attacker who can write the application's storage is outside the
v1 threat model. This is to be decided again before a production release.

Why it is a decision and not a gap in the crash model: crash consistency
(sections 3 and 7) holds. Each stored value authenticates under its own key
name only, with no version or counter (`core-storage`, `put_row`/`get_row`),
so an older value of the same key reads as valid. The send precondition
"session is the record loaded" (section 3) is satisfied by a restored
record, so nothing in the transition detects it.

Consequences observed on `main` @ `090bb17` with synthetic data, in temporary
tests that were not committed. The store was closed, one earlier row of the
`kv` table was written back with plain SQL, and the store was reopened:

- **Session record of the sender:** the next send of a new logical message
  encrypts again at a chain position already used, with the same message key
  (the key is derived deterministically from the restored chain key). The
  nonce is random per encryption and differed; nonce reuse was not observed.
  A receiver that already consumed that position rejects the new ciphertext;
  one that has not accepts whichever arrives first. The rejected message stays
  in the sender's outbox, unacknowledged. Later messages are accepted. A send
  repeated with the original logical id is still answered from its `sendid:`
  and `outbox:` records, without encrypting.
- **Outbox record after acknowledgement:** the delivered message is pending
  again and is retransmitted with its stored bytes; no new ciphertext and no
  ratchet change. The receiver reports a duplicate; the next new send is
  normal.

Not examined: rollback across a DH-ratchet step, receiver-side records, the
`sendid:` record, and network-layer receipts.

When this is revisited, a fix must state which of the two rollbacks it
resists and against which attacker, and add the experiments above as tests
that fail before it and pass after it.

Retention: `seen:` and `sendid:` records are kept for the life of the session
and beyond, including across its removal (about 40 bytes of payload plus the store's per-row overhead per
message). They are never listed, so they cost disk space, not time.

## 9. Compatibility

`SESSION_CHECKPOINT_V1`, `RATCHET_STATE_V1`, `PREKEY_BUNDLE_V1`,
`INITIATOR_HANDSHAKE_V1`, `PERSISTED_PREKEY_RECORD_V2` and the message format
`header(40) || ciphertext` are unchanged. `PROVISIONAL_HANDSHAKE_RECORD_V1`
(`hsin:`) is new and local. A responder session stored by an earlier build at
generation 0, before any message authenticated, is still loaded as a session;
it reads as `AwaitingPeer`, not `Established`, until a message from the peer
is accepted on it. It is not migrated in place: it is retired when a new
handshake from the same peer is recorded (section 4b), and otherwise stays
until a message authenticates on it. The FFI messaging calls change shape
(`send_message` takes a client message id and returns an outcome;
`receive_message` returns a record) and `remove_session` and `abandon_outgoing` are new (later,
`acknowledge_outgoing` and `abandon_outgoing` stopped being exported); the bytes on
the wire are identical. A provisional record may also sit beside this device's
own unconfirmed initiator session (section 4c, same key and format); how
records left by earlier builds are read is stated there. The exported
`remove_session` now also deletes such a record.

## 10. Verification plan

| property | test | evidence class |
|---|---|---|
| one commit ↔ one installed successor; output only after commit | core-protocol unit tests over S1 | runtime |
| outbox bytes identical across retries and restarts | core-protocol + mobile-ffi | runtime |
| duplicate ciphertext: no second acceptance, no ratchet step | core-protocol + mobile-ffi | runtime |
| stale / competing instances cannot both publish | two connections, two threads, two `ArciumCore` | runtime |
| responder: a handshake creates only a provisional record; the first authenticated message creates the session with its prekey rotation, once, atomically | `messaging/tests/first_contact.rs`, `mobile-ffi` `tests::responder`; process abort before/after the promotion's commit; race hook on a second connection | runtime; process crash; unknown outcomes simulated |
| a handshake beside an own unconfirmed session: recorded and nothing else, refused for any other session, deleted by the confirming receive, the removal and the forgetting; the authentication check writes nothing and accepts only a message of that handshake's session; competing connections | `messaging/tests/beside.rs`; `messaging/tests/crash.rs` (`process_killed_around_recording_beside_*`, `process_killed_during_a_confirming_receive_*`); `mobile-ffi` `tests::false_conflict` | runtime; process crash; race hook on a second connection |
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
