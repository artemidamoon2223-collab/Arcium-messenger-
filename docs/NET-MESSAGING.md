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
 NetworkMessenger ──TCP── SEND ──▶ mailbox[B] ──FETCH/DELETE── NetworkMessenger
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
- **Responder.** A handshake is answered only if its sender is a pinned
  contact and the initiator key inside the handshake equals that contact's
  X25519 key. Anything from an unknown sender is dropped.

There is no trust on first use in the application. (The CI peer in
`tests/net_peer.rs` pins on first use; it is a test harness.)

## 3. Transport: the relay

`RELAY_PROTOCOL_V1` (`crates/relay/src/protocol.rs`): length-prefixed frames,
five operations — PUT_BUNDLE, GET_BUNDLE, SEND, FETCH, DELETE. Exact decoding;
frames up to 1 MiB, envelopes up to 64 KiB, bundles up to 1 KiB.

**Retention.** An envelope stays in the recipient's mailbox until the recipient
deletes it, it is 7 days old, or the relay stops (nothing is on disk). A
mailbox holds at most 4096 envelopes; a SEND beyond that is refused, never
made room for. Identical bytes still stored are not stored twice.

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
does not exist yet stays on the relay until its handshake arrives. A message
that does not decrypt, is malformed or comes from an unknown sender is
deleted from the relay and changes nothing.

Handshake: retransmitted by the initiator until the session has received a
message from the peer (its receipt of OPEN). The responder answers it once; a
repeat, or any handshake from a peer it already has a session with, is
dropped. No session is ever replaced automatically: not on timeouts, not when
a peer is offline, not on a new handshake.

## 7. Failure handling

| failure | result |
|---|---|
| relay unreachable, connection lost | `sync` reports it; nothing local changes; next sync repeats |
| SEND answer lost | the envelope may be stored; it is sent again (the relay stores it once, or the recipient sees a duplicate) |
| FETCH answer lost | nothing processed; next fetch returns the same |
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
- A second initiator racing for the same one-time prekey fails the same way.
- Read receipts; multi-device; group messaging; attachments.
- Envelopes waiting for a missing handshake occupy the first slots of each
  FETCH (at most 256 are returned per round).
- Everything S2-B2 does not provide: power-loss durability, rollback
  detection, exactly-once delivery to the application.

## 9. Verification

| property | test | evidence class |
|---|---|---|
| first contact, identity binding, stranger drop | `tests::network` V1 tests | runtime, local relay over TCP |
| both directions, restarts, consistent histories | `both_directions_and_both_histories_survive_restarts` | runtime |
| offline recipient | `messages_to_an_offline_recipient_wait_on_the_relay` | runtime |
| relay outage; broken SEND/FETCH/DELETE/receipt | `a_relay_outage…`, `broken_connections_at_each_step…` (TCP proxy) | runtime; faults injected at the socket |
| process death at each boundary | `tests::network_crash` (child `abort()`) | process crash |
| replay, reorder, malformed, forged and cross-session receipts, replayed handshake, lost receipt | `tests::network` V6 tests | runtime |
| two OS processes | `a_peer_in_another_process_answers_over_the_relay` | runtime |
| Android app ↔ host peer through a relay | `NetworkMessagingInstrumentationTest` on the emulator | Android runtime (emulator + host) |
| plaintext never reaches the relay | relay canary in every test | runtime |
