# Network messaging — end-to-end encrypted messages between devices

Builds on S2-B2 (`docs/S2-B2-DURABLE-MESSAGING.md`): the durable outbox and
inbox, one committed transition per message, and the session lifecycle. This
layer only moves bytes that layer has already committed. It never encrypts,
decrypts or advances a ratchet on its own.

Code: `crates/relay` (relay, protocol, client), `crates/mobile-ffi/src/network.rs`
(`NetworkMessenger`), `crates/mobile-ffi/src/contacts.rs` (contact cards).

## 1. Architecture

```
 device A                        relay (untrusted)                  device B
 NetworkMessenger ──TCP── SEND ──▶ mailbox[B] ──FETCH_AFTER/DELETE── NetworkMessenger
   │ outbox (S2-B2)             bundles[A], bundles[B]            │ inbox (S2-B2)
   └ ArciumCore ─ X3DH, Double Ratchet, encrypted store            └ ArciumCore
```

Alternatives considered:

| option | why not (now) |
|---|---|
| direct peer-to-peer | phones behind NAT cannot accept connections; an offline peer receives nothing |
| Tor onion services (`core-transport`, arti) | the crate is a stub (`TODO.onion`), arti is not bootstrapped anywhere, and it cannot be exercised in CI without the Tor network; kept as future work |
| a third-party push or messaging service | an external account and service, which needs the owner's approval |
| **untrusted store-and-forward relay** | chosen: works with offline peers, runs locally and in CI, needs nothing external, and nothing about it is trusted |

The relay is a development and test relay (`arcium-relay`): in memory, no TLS,
no authentication. Deploying a public one is a separate decision.

## 2. Identity

A device has two identity keys: X25519 (sessions are keyed from it) and
Ed25519 (signs its prekeys; the signed object binds the X25519 key, F-2).

- `contact_card()` is `CONTACT_CARD_V1`: `0x01 || x25519_pk(32) || ed25519_pk(32)`.
  Cards are exchanged **out of band** (QR code, another channel) and compared
  with `contact_card_fingerprint` (16 bytes of
  `SHA-256("ARCIUM-CONTACT-CARD-V1" || card)`, in hex).
- `add_contact(card)` pins it. A different card for a pinned X25519 key is
  refused (`ContactIdentityChanged`); nothing is replaced silently.
- **Initiator.** `start_session(peer)` fetches the peer's bundle from the relay
  and refuses it (`PeerIdentityMismatch`) unless both keys equal the pinned
  card. X3DH then checks the prekey signature under that pinned Ed25519 key.
- **Responder.** A handshake is considered only if its sender is a pinned
  contact and the initiator key inside the handshake equals that contact's
  X25519 key. Anything from an unknown sender is dropped. Both keys are
  public and the sender field is unauthenticated, so this only picks the
  contact: the handshake is recorded as provisional and creates no session.
  The session is created when the initiator's first message (OPEN)
  authenticates under the keys the handshake derives — which requires the
  secret of the pinned identity key (S2-B2 section 4). The relay and Kotlin
  never decide that.

There is no trust on first use in the application. (The CI peer in
`tests/net_peer.rs` pins on first use; it is a test harness.)

## 3. Transport: the relay

`RELAY_PROTOCOL_V1` (`crates/relay/src/protocol.rs`): length-prefixed frames,
six operations — PUT_BUNDLE, GET_BUNDLE, SEND, FETCH, DELETE, FETCH_AFTER.
Exact decoding; frames up to 1 MiB, envelopes up to 64 KiB, bundles up to
1 KiB.

**Paging.** Each stored envelope gets a sequence number from one relay-wide
counter: it starts at 1, only grows, and a relay that has used `u64::MAX`
refuses SENDs with FULL instead of wrapping. `FETCH_AFTER(recipient, after,
max)` returns the unexpired envelopes numbered above `after` in ascending
order: at most `max` and 256 (`MAX_FETCH`) of them, and no more than fit in
one frame, so at least 15 (`MIN_PAGE`, the number of 64 KiB envelopes that
fit) while more follow. FETCH is FETCH_AFTER with `after = 0`. Entries deleted
or expired between requests are absent; entries appended meanwhile have
larger numbers. Sequence numbers are transport positions: they are not
authenticated, say nothing about sender or delivery, and are never stored by
the client. A relay built before FETCH_AFTER answers it with BAD_REQUEST, as
it answers every operation byte it does not know; the client reports that as
a failed sync and has no fallback to FETCH.

**Reading a mailbox (one sync round).** Two passes over the mailbox, each
paging forward from the start with FETCH_AFTER:

1. handshakes: every handshake is processed, everything else is skipped;
2. everything else, up to the last sequence number pass 1 reached (envelopes
   appended after that wait for the next round).

Handshakes go first so that a message whose handshake sits later in the
mailbox (a newer handshake behind an older first message, or behind many
kept envelopes) finds it recorded. After each pass the client deletes exactly
the envelopes that pass processed to completion (accepted, duplicate, or
dropped); envelopes kept for a missing handshake and envelopes of the other
kind stay, and paging moves past them. A round starts again from the
beginning, with one exception: after a round its time budget cut short
(section 7), the next round's passes start where that round's passes stopped,
so that both move on even when whole pages hold only kept envelopes. These
positions are held in memory only. They are a starting point chosen by the
untrusted relay, never evidence of anything: any failed round, and every
round that reaches the end of the mailbox, puts them back to the beginning,
and everything skipped is read again.

Bounds per round, whatever the relay does: each pass reads at most 4096
envelopes (`MAX_SCAN_ENVELOPES`, a whole mailbox) and at most 274 pages
(`MAX_SCAN_PAGES` = 4096 / 15 rounded up); so at most 548 FETCH_AFTER and 2
DELETE requests, at most one page (one 1 MiB frame) in memory, and at most
4096 envelopes decrypted or verified per pass. An honest relay stores an
envelope's bytes unchanged, so each is processed in one pass only: at most
4096 per round (8192 if the relay swaps an envelope's kind between the
passes). A pass also ends early on a page shorter than 15 or on reaching its
upper bound, so a mailbox of fewer than 15 envelopes costs two FETCH_AFTER
requests (one if it is empty). A relay that
returns more than asked for, or numbers that do not increase past the cursor,
ends the round with an error.

Bounds in time (section 7): every request, from writing it to reading the
whole answer, ends within 30 s; a round stops starting requests after 120 s.
Each pass still reads its first page, so a round that ran out moves both
passes on, and the next round continues with what is left.

The price: kept envelopes are read again in both passes of every round, so a
round transfers up to twice the scanned part of the mailbox (at most
2 × 4096 × 64 KiB with the largest envelopes), where a single FETCH read at
most one page. Keeping a round bounded, not cheap, is what this provides.

**Retention.** An envelope stays in the recipient's mailbox until the recipient
deletes it, it is 7 days old, or the relay stops (nothing is on disk). A
mailbox holds at most 4096 envelopes; a SEND beyond that is refused, never
made room for. The capacity can be set lower (`--max-mailbox N`,
`RelayConfig::max_mailbox`), never higher: 4096 is what one round's scan
covers (`MAX_SCAN_ENVELOPES`), and `serve` refuses 0 or more than 4096 with
`InvalidInput` before starting anything, so no configuration of this relay
holds entries a round cannot reach. Identical bytes still stored are not
stored twice.

**Delivery does not depend on retention.** The sender keeps every text until
the recipient's receipt arrives, and sends it again after
`retransmit_after_ms`, then after twice as long each time, up to 5 minutes
(section 7). A relay that loses, withholds or restarts only delays
delivery, with one exception: if more than `MAX_SKIP` (1000) consecutive
messages of one sending chain are lost (receipts included, which are never
sent again once the relay has stored them), the recipient refuses every
later message of that chain and that direction stops for good (tracker
R-14).

`ENVELOPE_V1` (what the relay stores):
`"ARN1" || kind(1) || sender_x25519_pk(32) || body`, kind 1 = the unchanged
84-byte `INITIATOR_HANDSHAKE_V1`, kind 2 = the unchanged
`header(40) || ciphertext`, kind 3 = a 129-byte `HANDSHAKE_REFUSAL_V1`
(section 6). The sender field is unauthenticated and only picks the session; a
message decrypts only under the session (keys and AD) that produced it, and a
refusal counts only if its tag checks for the sender's pinned identity key and
ours.

**What the relay and the network see:** the recipient's and sender's X25519
identity keys, when each device connects, envelope sizes and timing, every
published bundle, the handshake bytes, and that a refusal was sent and its
reason byte (inside the authenticated bytes, which the relay can read but not
change). A refusal shows that its sender answered a handshake naming the
recipient, so whoever reads the mailbox learns that the sender has the
recipient as a contact; but the refusal is no proof of it to anyone else (see
section 6). They do
not see plaintext, identity
or prekey secrets, ratchet state or checkpoints. There is no anonymity and no
Tor: a network observer sees the same as the relay, and the relay can link
sender, recipient and time of every message.

## 4. Messages inside the ratchet

`PAYLOAD_V1`, the plaintext of each ratchet message (the wire format is
unchanged; this is only what is encrypted):

| type | content | consumed by |
|---|---|---|
| 1 TEXT | application bytes | the application (`received_texts`, `mark_read`) |
| 2 RECEIPT | 1–256 message ids | the network layer |
| 3 OPEN | nothing | the network layer |

OPEN is the initiator's first message. It lets the responder send before the
initiator's first text (a responder has no sending chain until it receives).

Client message ids in the outbox: `t || app_id` (texts, app id 1–63 bytes),
`r || message_id [|| round]` (receipts), `o || sha256(handshake)[0..8]`
(OPEN: one per session, so a session that replaces an abandoned one commits
its own; builds before this one used `o` alone). `send_message` refuses all
of these.

## 5. Acknowledgements

| level | means | evidence |
|---|---|---|
| transport acceptance | the relay stored the envelope | relay SEND answer; unauthenticated |
| durable receipt and cryptographic acceptance | the recipient's ratchet authenticated the message and committed it to its inbox | these happen in one S2-B2 transaction, so one receipt covers both |
| application processing | the recipient's application called `mark_read` | **not transmitted** in this version |

- A text leaves the sender's outbox (`acknowledge_outgoing`) only on a RECEIPT
  from the recipient: a ratchet message of that session naming the exact
  message id. A forged receipt does not decrypt; a receipt from another
  session names ids that session never sent and confirms nothing; a replayed
  receipt is a duplicate and changes nothing.
- The recipient commits the receipt when the text is accepted (in the same
  sync, before deleting it from the relay), so a crash cannot lose it.
- Receipts are not acknowledged: a receipt leaves the outbox once the relay
  accepted it. If it is lost, the sender sends the text again; the recipient
  receives a duplicate and commits a new receipt (at most one per message per
  minute). Only a message that was answered when first accepted (a text or
  OPEN) is answered again; a duplicate of a receipt, or of a payload this
  build does not know, is not answered.
- A missing receipt is never read as non-delivery; the text stays pending.
- Neither `acknowledge_outgoing` nor `abandon_outgoing` is exported through
  UniFFI: only this layer takes a text out of the outbox, on a receipt, or
  in `resolve_session_conflict`, or when the user deletes the contact
  (`delete_contact`), which marks it abandoned.
- The history never reads a text missing from the outbox as delivered by
  itself. It reads the durable send record (`Messenger::prior_send`, keyed
  by the peer): acknowledged is `Delivered`, abandoned is `NotDelivered`,
  and any other answer, including a record of another message, changes
  nothing. Abandoning rewrites that record in the transaction that empties
  the outbox, and the record and the outbox are read in one transaction
  (also inside `send`), so even another connection's abandonment is never
  read halfway as an acknowledgement. A text committed while
  `resolve_session_conflict` runs (after its NotDelivered pass) still ends
  `NotDelivered`.
- The exported raw `send_message` refuses the client ids this layer sends
  under (starting with `t` or `r`, or `o` alone). `send_text` and
  `chat_send` share the text id space (`t` + app id) and exclude each other
  per app id and peer: `send_text` records a claim (`chat-r:`), `chat_send`
  an entry (`chat-o:`), each in an IMMEDIATE transaction that checks for the
  other's record first; `chat_send` also refuses an app id with a text
  already committed and no entry (sent before claims existed). The ids
  themselves and every stored record are unchanged: no migration. Nor is
  anything repaired: an entry already shown `Delivered` by the old rule
  stays so, and an entry a build without claims linked to a `send_text`
  message keeps following that message.

## 6. State machines

Outgoing text: `committed (outbox)` → `published (relay accepted; in memory,
repeated after a restart)` → `delivered (receipt; outbox record deleted,
send-id kept)` or `abandoned (abandon_outgoing)`. Repeating `send_text` with
the same app id never encrypts again (S2-B2).

Incoming envelope: fetched → `accepted (inbox committed, receipt committed)` →
deleted from the relay → shown → `mark_read (seen)`. A message whose session
does not exist yet stays on the relay until its handshake arrives; it is not
copied, acknowledged or counted as delivered meanwhile, and it does not hide
the envelopes behind it (section 3, reading a mailbox). A message
that does not decrypt, is malformed or comes from an unknown sender is
deleted from the relay and changes nothing.

Handshake: retransmitted by the initiator until the session has received a
message from the peer (its receipt of OPEN). The responder records it as
provisional (a repeat changes nothing; a different handshake for that contact
replaces it, since neither has authority) and creates the session when the
first message authenticates under it. A handshake from a peer it already has
a session with is dropped. No session is ever replaced automatically: not on
timeouts, not when a peer is offline, not on a new handshake. The one
exception is a responder session an earlier build stored on receipt of a
handshake and nothing has happened to since (S2-B2 section 4b): the network
layer only checks that shape, read-only, and passes the handshake to
`establish_session_responder`, which alone decides whether to retire it. A
refusal there is a drop, as for any existing session.

A message with no session yet either creates it (it authenticates under the
recorded handshake), is deleted (it does not), or waits on the relay (no
handshake recorded). If the prekeys the recorded handshake names rotated or
were consumed by another contact's first message since, the message is
deleted and the handshake flagged as refused.

**Refusals.** When a handshake can never be answered (the prekeys it names
were consumed or rotated, and no session holds it), the responder says so.
Typical case: two contacts write to a device for the first time while it is
offline; both handshakes name the one one-time prekey its bundle carried, and
only the first can be accepted.

- When the responder refuses a handshake from a pinned contact with no
  session holding it, with `OneTimePrekeyUnavailable`, `OneTimePrekeyRequired` or
  `StaleSignedPrekey`, it sends `HANDSHAKE_REFUSAL_V1`:

  ```text
   0  32  refuser_identity_dh_pk
  32  32  initiator_identity_dh_pk
  64  32  sha256(INITIATOR_HANDSHAKE_V1 bytes)
  96   1  reason   1 one-time prekey unavailable, 2 required, 3 stale signed prekey
  97  32  tag
  ```

  The tag (`core_crypto::refusal_mac`) is a MAC over bytes 0..97, keyed by
  HKDF-SHA256 over the X25519 of the two identity keys, with info
  `"arcium/handshake-refusal-mac/v1" || refuser_pk || initiator_pk`. Only the
  two parties can make or check it, and the key for "A refuses B" differs from
  the one for "B refuses A". It is a MAC and not a signature on purpose: a
  handshake is not signed, so anyone who knows both keys can elicit a refusal
  with a forged handshake naming a contact. The initiator could have made the
  same bytes alone, so a refusal proves nothing to a third party about whom
  the refuser has pinned. An all-zero DH output (a low-order key) gives no
  tag and is never accepted. The price of a MAC: whoever holds the
  initiator's own identity secret can also make a refusal it accepts (section
  8).

  A refusal is sent at most once per refused handshake and at most once per
  contact per 10 minutes, in memory (a restart may send one more, and so may
  a lost answer to a SEND the relay did carry out; a second copy names a
  handshake that is gone by then and is dropped). A first
  message refused for its prekeys sends none; the initiator's next
  retransmission of the handshake is refused and answered. A refusal the relay
  does not store (the initiator's mailbox is full), and one whose SEND loses
  the connection, stays queued for the next round, within the same process,
  as does one the round's budget leaves unsent; the wait after a relay
  refusal is that of section 7. A relay refusal does not end the round.
- The initiator acts on a refusal only if its tag checks for the sender's
  pinned identity key and ours, it names those two keys, and it names the
  handshake of our own session with the sender, on which nothing was received
  yet. Anything else is dropped and changes nothing (a forged, foreign,
  replayed or late refusal).
- Acting on it, the initiator gives its session up as
  `resolve_session_conflict` does: committed texts `NotDelivered`, then
  abandoned, then the session removed (S2-B2 section 6a). It ends a conflict
  with that contact and starts a new session from the contact's current
  bundle at once. Texts still queued go out in the new one; texts marked
  `NotDelivered` are not sent again (the user can send them again). If the
  new session cannot start then (no bundle, no relay, a crash), the next
  queued text starts it. Each step repeats safely after a crash: the refusal
  stays on the relay until the round deletes it, and once the dead session is
  gone it no longer matches.
- A genuine refusal is final: the responder sends it only where the
  handshake cannot become answerable later (a consumed one-time prekey is
  never reissued, a rotated signed prekey never returns). The responder's
  bundle is published at the start of every round, before handshakes are
  processed, so the bundle the initiator fetches after a refusal names the
  current prekeys.

## 7. Failure handling

Time bounds (`relay::client::REQUEST_DEADLINE`, `network::ROUND_BUDGET`,
`network::RETRANSMIT_CAP`):

- **One request: 30 s.** Every read and write on the connection waits at most
  `timeout_ms`, and the request as a whole (writing it, reading the whole
  answer) at most 30 s; past that it fails as a lost connection. A relay that
  trickles bytes cannot hold a round open. A page (at most one 1 MiB frame)
  therefore needs a link of about 35 KiB/s to arrive; on a slower link a
  full page of large envelopes cannot be read (no adaptive paging).
- **One round: 120 s of relay requests.** The budget is checked before every
  page of a pass after its first, and before every send. When it runs out,
  the pass stops after the page in hand, deletes what it processed, and the
  round's report carries the line `round budget exhausted: the rest follows
  in the next round`. That line is not a network error (it does not start
  with `network:`): the relay was reached, and the application neither shows
  the link as offline nor slows its rounds down for it. Nothing processed is
  lost or processed again. The next round continues after the last sequence
  number each pass reached (section 3), so a mailbox larger than one round
  can read is worked through over several rounds; once both passes reach the
  end, rounds start from the beginning again. A round that ran out ends
  within the budget plus a few request deadlines (the request in flight, each
  pass's first page and deletion).
- **Retransmission: 5 s, doubling, at most 5 minutes apart.** Each message or
  handshake waits `retransmit_after_ms` after its first send and twice as
  long after each further one, up to 5 minutes: at most 9 sends in 10
  minutes instead of about 120. Kept in memory: after a restart everything
  pending is sent once more and the waits start again. This spaces the
  sends only; what is sent, and when a text leaves the outbox, is unchanged.

| failure | result |
|---|---|
| relay too slow for a request, or trickling bytes | the request fails after 30 s; the round ends as for a lost connection |
| round budget exhausted | processed envelopes are deleted, the report says so (not as a network error), the next round continues where the passes stopped |
| relay unreachable, connection lost | `sync` reports it; nothing local changes; next sync repeats |
| relay refuses to store an envelope for a recipient (its mailbox is full) | nothing more is sent to that recipient in this round; the round goes on for every other recipient and for this device's own mailbox. The report carries `relay refused N recipient(s): Full`, which is not a network error. Nothing is sent to that recipient until a wait has passed (as between retransmissions: `retransmit_after_ms`, doubling with each refusal in a row, at most 5 minutes; kept in memory), so its envelopes keep their order. The first envelope stored for it ends the wait. Texts stay pending; a refused receipt is not acknowledged and is sent later |
| SEND answer lost | the envelope may be stored; it is sent again (the relay stores it once, or the recipient sees a duplicate) |
| FETCH_AFTER answer lost (any page), connection lost between pages | the round stops; what the current pass processed is committed but not yet deleted, and comes back next round as a duplicate |
| process death between pages | same as above: committed acceptances are duplicates next round, nothing is shown twice |
| relay restarts (empty) mid-round | the round fails; senders retransmit what has no receipt |
| DELETE lost | the envelope comes back as a duplicate: no second acceptance, a new receipt |
| crash after a text is committed | the stored bytes are sent after restart |
| crash after acceptance / receipt commit / delete | the inbox holds the message once; its receipt is committed or re-derived from the inbox |
| crash after a receipt is accepted | applied from the inbox at the next sync |
| commit outcome unknown | S2-B2 recovery (`recover_session`), which this layer runs itself: at the start of the next round, before it commits a queued text, and when a message for that session is fetched; the envelope stays on the relay |

## 8. Not provided

- Anonymity, metadata protection, Tor.
- Authentication of relay clients: anyone reaching a relay can read (only
  ciphertext) or delete a mailbox, or replace a bundle (refused by the
  initiator's identity check). Denial of service is possible.
- Refusal feedback beyond the refusal of section 6: a relay can withhold a
  refusal (the initiator then keeps retransmitting, as before refusals
  existed), and a refusal lost after the relay accepted it is not sent again
  for that handshake until the responder restarts (section 6: at most once
  per refused handshake); until then the initiator waits (tracker R-16). A refusal queued but not
  yet stored is lost if the responder's process ends.
- Hiding whom a device knows from a reader of the mailboxes. A refusal of a
  forged handshake shows such a reader that the refuser has the named
  initiator as a contact (it proves it to nobody else); so does a message
  kept rather than deleted (section 3). Closing this needs relay
  authentication.
- Protection against key-compromise impersonation of refusals. A refusal is
  authenticated by a MAC both parties can make, so whoever holds the
  initiator's identity secret can make one the initiator accepts, and so end
  its pending first contact (its texts become `NotDelivered`) and make it
  start again. That secret already allows impersonating the initiator.
- Automatic resending of texts a refusal or a conflict resolution marked
  `NotDelivered`.
- One provisional handshake per contact. Whoever can put envelopes in the
  mailbox (the relay has no authentication) can keep replacing a contact's
  recorded handshake before its first message arrives; the genuine one is then
  retransmitted and takes over. That delays first contact; it creates no
  session and consumes no prekey. Each such first message costs the responder
  one X3DH and one ratchet step.
- A second initiator racing for the same one-time prekey is refused and
  starts again (section 6). With k contacts racing, the k-th may wait up to
  about 10 minutes per further refusal (the per-contact limit).
- Simultaneous initiation: if both users start a session with each other
  before either handshake arrives, each device holds an unconfirmed initiator
  session and drops the other's handshake, so neither proceeds (no fork: each
  side's messages fail to decrypt at the other and write nothing). Nothing
  resolves it automatically. The conflict is recorded and shown, and the user
  of one device resolves it (section 10).
- Read receipts; multi-device; group messaging; attachments.
- Protection against a full mailbox. Paging (section 3) only stops kept
  envelopes from hiding later ones. Anyone who can reach the relay can still
  fill a mailbox to its 4096 entries (SEND is then refused) or delete from
  it. A full mailbox stops delivery to its owner only: a sender's round goes
  on for its other contacts (section 7). And a relay that keeps appending
  can keep a round busy up to its bound with the rest of the mailbox out of
  reach until the next round. No relay availability or denial-of-service
  resistance is claimed.
- Everything S2-B2 does not provide: power-loss durability, rollback
  detection, exactly-once delivery to the application.

## 10. Conversations

`network/chat.rs`: what an application shows. The durable layer keeps a text
only until its receipt (outgoing) or until it is marked read (incoming), so
the chat layer keeps a history per contact in the same encrypted store: one
entry per logical message, never written by the ratchet.

| entry state | means |
|---|---|
| `Queued` | recorded under the application's id; not encrypted (no session that can send yet) |
| `Pending` | committed to the outbox (encrypted) |
| `Transmitted` | the relay accepted it; nothing is known about the peer |
| `Delivered` | the peer's authenticated receipt arrived (its device committed it); not a read receipt |
| `NotDelivered` | given up after a conflict resolution; the peer never accepts it |
| `Received` | a text from the peer |

- **Sending.** `chat_send(peer, app_id, text)` records the entry first, then
  commits it with `send_text` under the same id when a session exists that
  can send (a responder session of S2-B2 section 4b cannot; the text waits,
  and the round goes on to fetch). Every
  step repeats with that id, so a retry or a crash between the steps finds
  the committed message; a text is never encrypted twice. A state only moves
  forward.
- **Receiving.** A received text is recorded with an index on its message id
  in one transaction, then marked read. After a crash between the two it is
  listed again and skipped: each text appears once in the history. Delivery
  from the inbox stays at least once; the history deduplicates it.
- **Delivered.** A committed text leaves the outbox only on the peer's receipt
  or when abandoned, and the durable send record tells the two apart
  (section 5). A text that left the outbox is `Delivered` only if its record
  says acknowledged for its own message id; with or without a session.
- **Sessions.** `sync_conversations` runs `sync` first, so a waiting handshake
  from the contact and its first message are accepted, and only then starts a
  session for a contact with queued texts and none yet. A recorded handshake
  whose first message has not arrived is not a session and does not stop that
  (both sides then hold their own unconfirmed session: the conflict below).
  `Established` means a message from the contact authenticated under the
  session here, and nothing else. A bundle that does not match the pinned
  card is refused and flagged (`identity_mismatch`); a missing bundle leaves
  the text queued with a note.
- **Conflict.** A handshake from a contact whose session here is an
  unconfirmed start of our own is still dropped, and the conflict is
  recorded. Only the device with the greater identity key may resolve it
  (`resolve_session_conflict`), and only when its user asks. That device marks
  its committed texts `NotDelivered`, abandons them, removes its unconfirmed
  session (allowed by S2-B2 section 6a: nothing was received on it), and waits
  for the contact's handshake, which the contact retransmits. The user can
  send those texts again as new messages. Nothing is removed automatically.
  A text committed concurrently, between the marking and the abandoning, is
  abandoned too and shown `NotDelivered` from its record; one committed after
  the abandoning makes the removal refuse (`PendingOutgoing`), and calling
  again completes it.
  A handshake that is not the contact's current one can raise a false
  conflict: a replayed old one, or a forged one (it is built from public
  bytes, and the relay does not authenticate senders). Resolving a false
  conflict is not harmless. If the contact goes on to accept this device's
  original handshake, the two devices dead-end: this device waits for a
  handshake that never comes, and the contact keeps an established session
  whose messages this device cannot read. Nothing resolves that
  automatically; the way out is deleting the contact on both devices (below;
  tracker R-13; options in `docs/SESSION-RECOVERY-OPTIONS.md`). On the
  device with the smaller key, a false conflict clears by itself once the
  contact confirms the session.
- **Deleting a contact.** `delete_contact(peer)`, on the user's request,
  removes in one store transaction the pinned card, the name and flags, the
  whole history, and the session in any state (established, unconfirmed, in
  conflict, unreadable or absent) with its handshakes, pending outgoing
  texts and pending incoming messages (S2-B2 section 6a, "Forgetting a
  peer"). Pending texts are marked abandoned there, so none is ever read as
  delivered; the `seen:` and `sendid:` records stay, so nothing is
  encrypted twice and nothing already received is new again. Undelivered
  texts are lost, and the contact is told nothing: it keeps its session,
  and drops a new handshake from this device while it does. To start
  again, both users delete each other and exchange cards again; the next
  text then starts a new session. This is the way out of a session that
  can no longer progress, such as the dead end after a false conflict was
  resolved. Deleting again, or deleting someone who is not a contact, is
  harmless.
- **Reading in pages.** Entries are numbered 1, 2, … per contact: each takes
  the next number in the transaction that writes it, and none is deleted.
  `chat_entries_page(peer, before_seq, limit)` returns the `limit` entries
  (1 to 200) before `before_seq`, or the newest ones, oldest first, read by
  number. `chat_entries` still returns the whole history. A number can be
  missing only from a damaged store: every read skips it (a page then walks
  further back, so it still holds up to `limit` entries), while an entry
  that exists but cannot be read is still an error (R-10).
- **What a round reads.** A record per contact, `chat-open:v1`, lists the
  numbers of outgoing entries not yet final (`Queued`, `Pending`,
  `Transmitted`). It changes in the transaction of every entry change that
  adds or removes one. Rounds, sends and the giving up of a session walk it
  instead of the history. A history written before it existed has none; it
  is built once, in one transaction, from the entries. The conversation list
  reads the last entry and the entries not yet seen, not the history.
  Listing a store namespace (the outbox, the inbox, the contacts) is still a
  scan of the whole SQLite table on every call (`list_keys_with_prefix`), so
  a round keeps a cost that grows with the store's size; it no longer
  decrypts the history.
- **Not provided.** Sync while the application is closed; unread state across
  devices; a sender timestamp (entries carry the local time they were
  recorded). The conversation screen reads a window of the newest entries
  through `chat_entries_page` and widens it by 50 on "load earlier"
  (`loadWindow` in `android/.../ui/chat/ChatViewModel.kt`), so it no longer
  reads the whole history.

## 9. Verification

| property | test | evidence class |
|---|---|---|
| first contact, identity binding, stranger drop | `tests::network` V1 tests | runtime, local relay over TCP |
| a handshake alone is not a session; its first message creates it; a recorded handshake does not block simultaneous initiation | `tests::responder` | runtime, local relay over TCP |
| both directions, restarts, consistent histories | `both_directions_and_both_histories_survive_restarts` | runtime |
| offline recipient | `messages_to_an_offline_recipient_wait_on_the_relay` | runtime |
| kept envelopes never hide later ones: prefixes of 0–4095 entries, large envelopes, handshakes behind or after the prefix, mixed kept and deleted, deletes, appends and expiry between pages, a mailbox that never runs dry, a relay that breaks paging, lost answers, a stopped relay, process death between pages | `tests::mailbox_scan`; relay paging and the refusal of a capacity above 4096 in `crates/relay` tests | runtime, local relay over TCP; process crash |
| relay outage; broken SEND/FETCH/DELETE/receipt | `a_relay_outage…`, `broken_connections_at_each_step…` (TCP proxy) | runtime; faults injected at the socket |
| one recipient's full mailbox: the round goes on for everyone else, the wait and its doubling, order of the waiting texts, a refused receipt | `tests::send_refusal` | runtime, local relay holding 8 envelopes per mailbox; waits scaled down |
| process death at each boundary | `tests::network_crash` (child `abort()`) | process crash |
| request deadline against a trickling relay; round budget on a slow relay with every text received once; a cut round continuing past a page of kept envelopes; backoff to the cap | `tests::net_limits`, `relay` client tests | runtime, local sockets; time scaled down in tests |
| replay, reorder, malformed, forged and cross-session receipts, replayed handshake, lost receipt, a replayed receipt not answered | `tests::network` V6 tests | runtime |
| two OS processes | `a_peer_in_another_process_answers_over_the_relay` | runtime |
| Android app ↔ host peer through a relay | `NetworkMessagingInstrumentationTest` on the emulator | Android runtime (emulator + host) |
| plaintext never reaches the relay | relay canary in every test | runtime |
| conversation history, states, repeats, replays, forged bundle, conflict | `tests::chat` | runtime |
| first contact to an offline recipient: 2, 3 and 5 contenders, both key orders, a conflict after a refusal; refusal limits; forged, foreign, mismatched, swapped-role, replayed and late refusals; an elicited refusal the initiator can make alone and a third party cannot check; a refusal the relay refuses or whose connection breaks, sent later; process death at each restart step | `tests::first_contact` | runtime, local relay over TCP; process crash |
| refusal tag: both parties compute it, third parties cannot; bound to both keys, the roles and every field byte; low-order keys; byte-for-byte vector computed independently with Python `cryptography` | `core_crypto::refusal_mac` tests | unit; known answer |
| history pages (sizes 1, 7, 200, new entries while paging), the open-entry record against a full scan (random steps, a history from before the record, a conflict), process death after its writes | `tests::history_paging` | runtime; process crash |
| process death while sending from or receiving into the history | `tests::network_crash` (`chat_*` points) | process crash |
