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
kind stay, and paging moves past them. The cursor lives only in that call; a
new round starts again from the beginning.

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
`retransmit_after_ms`. A relay that loses, withholds or restarts only delays
delivery.

`ENVELOPE_V1` (what the relay stores):
`"ARN1" || kind(1) || sender_x25519_pk(32) || body`, kind 1 = the unchanged
84-byte `INITIATOR_HANDSHAKE_V1`, kind 2 = the unchanged
`header(40) || ciphertext`. The sender field is unauthenticated and only picks
the session; a message decrypts only under the session (keys and AD) that
produced it.

**What the relay and the network see:** the recipient's and sender's X25519
identity keys, when each device connects, envelope sizes and timing, every
published bundle, and the handshake bytes. They do not see plaintext, identity
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
`r || message_id [|| round]` (receipts), `o` (OPEN).

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
  minute).
- A missing receipt is never read as non-delivery; the text stays pending.

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

## 7. Failure handling

| failure | result |
|---|---|
| relay unreachable, connection lost | `sync` reports it; nothing local changes; next sync repeats |
| SEND answer lost | the envelope may be stored; it is sent again (the relay stores it once, or the recipient sees a duplicate) |
| FETCH_AFTER answer lost (any page), connection lost between pages | the round stops; what the current pass processed is committed but not yet deleted, and comes back next round as a duplicate |
| process death between pages | same as above: committed acceptances are duplicates next round, nothing is shown twice |
| relay restarts (empty) mid-round | the round fails; senders retransmit what has no receipt |
| DELETE lost | the envelope comes back as a duplicate: no second acceptance, a new receipt |
| crash after a text is committed | the stored bytes are sent after restart |
| crash after acceptance / receipt commit / delete | the inbox holds the message once; its receipt is committed or re-derived from the inbox |
| crash after a receipt is accepted | applied from the inbox at the next sync |
| commit outcome unknown | S2-B2 recovery (`recover_session`); the envelope stays on the relay |

## 8. Not provided

- Anonymity, metadata protection, Tor.
- Authentication of relay clients: anyone reaching a relay can read (only
  ciphertext) or delete a mailbox, or replace a bundle (refused by the
  initiator's identity check). Denial of service is possible.
- Refusal feedback for handshakes: a responder that refuses a handshake
  (stale prekey) tells nobody; the initiator keeps retrying until the user
  removes the session (S2-B2 section 6a).
- One provisional handshake per contact. Whoever can put envelopes in the
  mailbox (the relay has no authentication) can keep replacing a contact's
  recorded handshake before its first message arrives; the genuine one is then
  retransmitted and takes over. That delays first contact; it creates no
  session and consumes no prekey. Each such first message costs the responder
  one X3DH and one ratchet step.
- A second initiator racing for the same one-time prekey fails the same way.
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
  it, and a relay that keeps appending can keep a round busy up to its bound
  with the rest of the mailbox out of reach until the next round. No relay
  availability or denial-of-service resistance is claimed.
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
  or when abandoned; the chat layer abandons only after marking the entry
  `NotDelivered`. So, while the session exists, a text that left the outbox is
  delivered.
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
  A replayed old handshake can raise a false conflict; resolving it then only
  delays the conversation.
- **Not provided.** Sync while the application is closed; unread state across
  devices; a sender timestamp (entries carry the local time they were
  recorded).

## 9. Verification

| property | test | evidence class |
|---|---|---|
| first contact, identity binding, stranger drop | `tests::network` V1 tests | runtime, local relay over TCP |
| a handshake alone is not a session; its first message creates it; a recorded handshake does not block simultaneous initiation | `tests::responder` | runtime, local relay over TCP |
| both directions, restarts, consistent histories | `both_directions_and_both_histories_survive_restarts` | runtime |
| offline recipient | `messages_to_an_offline_recipient_wait_on_the_relay` | runtime |
| kept envelopes never hide later ones: prefixes of 0–4095 entries, large envelopes, handshakes behind or after the prefix, mixed kept and deleted, deletes, appends and expiry between pages, a mailbox that never runs dry, a relay that breaks paging, lost answers, a stopped relay, process death between pages | `tests::mailbox_scan`; relay paging and the refusal of a capacity above 4096 in `crates/relay` tests | runtime, local relay over TCP; process crash |
| relay outage; broken SEND/FETCH/DELETE/receipt | `a_relay_outage…`, `broken_connections_at_each_step…` (TCP proxy) | runtime; faults injected at the socket |
| process death at each boundary | `tests::network_crash` (child `abort()`) | process crash |
| replay, reorder, malformed, forged and cross-session receipts, replayed handshake, lost receipt | `tests::network` V6 tests | runtime |
| two OS processes | `a_peer_in_another_process_answers_over_the_relay` | runtime |
| Android app ↔ host peer through a relay | `NetworkMessagingInstrumentationTest` on the emulator | Android runtime (emulator + host) |
| plaintext never reaches the relay | relay canary in every test | runtime |
| conversation history, states, repeats, replays, forged bundle, conflict | `tests::chat` | runtime |
| process death while sending from or receiving into the history | `tests::network_crash` (`chat_*` points) | process crash |
