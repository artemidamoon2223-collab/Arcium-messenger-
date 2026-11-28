# Network messaging — end-to-end encrypted messages between devices

Builds on S2-B2 (`docs/S2-B2-DURABLE-MESSAGING.md`): the durable outbox and
inbox, one committed transition per message, and the session lifecycle. This
layer only moves bytes that layer has already committed. It never encrypts,
decrypts or advances a ratchet on its own.

Code: `crates/relay` (relay, protocol, client), `crates/mobile-ffi/src/network.rs`
and `network/` (`NetworkMessenger`), `crates/mobile-ffi/src/contacts.rs` (contact cards).

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
| Tor onion services instead of a relay | phones cannot host a reachable service reliably, and an offline peer still receives nothing; Tor is used on top of the relay instead: a relay at an onion address is reached through arti embedded in the app (section 3a) |
| a third-party push or messaging service | an external account and service, which needs the owner's approval |
| **untrusted store-and-forward relay** | chosen: works with offline peers, runs locally and in CI, needs nothing external, and nothing about it is trusted |

The app speaks `RELAY_PROTOCOL_V2` to a V2 relay (`arcium-relay --keys
FILE`, section 3): TLS 1.3 with the relay's pinned key, and mailboxes only
for their authenticated owners. It is configured with the relay's connection
string, and `NetworkMessenger` authenticates as the device's identity key on
every connection that reads, deletes or publishes (the DH with the identity
secret is computed inside `ArciumCore`, which never hands the secret out).
`RELAY_PROTOCOL_V1` (`arcium-relay` without `--keys`: no TLS, no
authentication, `host:port`) is kept for development only: debug builds of
the app accept it, release builds accept V2 connection strings only
(`messaging/RelayRules.kt`), and the failure-injection tests (their TCP
proxy reads plaintext frames) and most of the Android emulator scenarios in
CI still use it; the two-device job ends with both emulators on a V2 relay.
Either way the relay is in memory unless started with `--db FILE`. With
it, every accepted envelope, deletion and bundle is committed to that SQLite file before
the request is answered, and a restart loads it (envelopes past the TTL are
dropped); a change that cannot be committed is not answered and the connection
closes, so the client retries. Deploying a public one is a separate decision.

## 2. Identity

A device has two identity keys: X25519 (sessions are keyed from it) and
Ed25519 (signs its prekeys; the signed object binds the X25519 key, F-2).

- `contact_card()` is `CONTACT_CARD_V1`: `0x01 || x25519_pk(32) || ed25519_pk(32)`.
  Cards are exchanged **out of band** (QR code, another channel) and compared
  with `contact_card_fingerprint` (16 bytes of
  `SHA-256("ARCIUM-CONTACT-CARD-V1" || card)`, in hex).
- `add_contact(card)` pins it. A different card for a pinned X25519 key is
  refused (`ContactIdentityChanged`); nothing is replaced silently. A card
  whose X25519 key has low order is refused (`InvalidContactCard`, tracker
  R-24): X3DH refuses such a key, so no session could be made with it. A
  card an older build pinned is not checked again, though adding it again
  (or renaming the contact that way) is refused.
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
  secret of the pinned identity key, or a signed-prekey secret this device
  still holds (key-compromise impersonation, section 8; the signed prekey
  is rotated, tracker R-6) (S2-B2 section 4). The relay and Kotlin never
  decide that.

There is no trust on first use in the application. (The CI peer in
`tests/net_peer.rs` pins on first use; it is a test harness.)

## 3. Transport: the relay

`RELAY_PROTOCOL_V1` (`crates/relay/src/protocol.rs`): length-prefixed frames,
six operations — PUT_BUNDLE, GET_BUNDLE, SEND, FETCH, DELETE, FETCH_AFTER.
Exact decoding; frames up to 1 MiB, envelopes up to 64 KiB, bundles up to
1 KiB. The app uses it only in development (section 1).

**V2 (what the app uses).** `RELAY_PROTOCOL_V2` is
the same frames inside TLS 1.3, plus one operation, AUTH, and one error,
UNAUTHORIZED (`protocol.rs`, `auth.rs`, `tls.rs`):

- `arcium-relay keygen --out FILE --address HOST:PORT` makes the relay's
  Ed25519 TLS key and X25519 auth key, writes both secrets to a new file
  (mode 0600, never over an existing one) and prints the connection string
  `arcium-relay-v2:<host>:<port>:<tls_pin>:<auth_pk>`, where `tls_pin` is the
  SHA-256 of the TLS key's `SubjectPublicKeyInfo` (both in 64 lowercase hex
  digits; `address.rs` parses it strictly).
- The relay presents its TLS key as an RFC 7250 raw public key, so no
  certificate is involved. The client accepts the handshake only if that
  key's SHA-256 equals the pin, and checks the TLS 1.3 signature under it.
  No resumption, no early data, no SNI.
- After the handshake the relay sends `HELLO = 0x02 || challenge(32)`, fresh
  for every connection. To act for the owner `O` of a mailbox the client
  sends `AUTH O tag`, with
  `tag = HMAC-SHA256(k, challenge || exporter || O)`,
  `k = HKDF-SHA256(salt = "arcium-relay-auth-salt-v1", ikm = DH(id_sk, auth_pk), info = "arcium-relay-auth-v1")`,
  and `exporter` 32 bytes of this connection's TLS exported keying material
  (label `"arcium-relay-auth-v1"`). The relay checks it with
  `DH(auth_sk, O)`, in constant time. A tag is valid on its connection only;
  one AUTH is checked per connection. An owner key with the top bit set is
  refused (X25519 ignores that bit).
- Limits on both versions: at most 1024 open connections, 32 per IP address
  (`--max-connections`, `--max-connections-per-address`); one beyond is
  closed at once. A V2 connection must finish its TLS handshake within 10 s;
  a read or a write that waits 60 s closes the connection. The TLS key
  exchange is X25519 only.
- FETCH, FETCH_AFTER and DELETE need AUTH for the recipient, PUT_BUNDLE for
  the owner; otherwise UNAUTHORIZED, and nothing is read or changed. SEND
  needs AUTH as the envelope's sender: the relay stores an envelope only if
  its sender field (bytes 5..37 of `ENVELOPE_V1`,
  `relay::protocol::ENVELOPE_SENDER`) is the authenticated owner's key, and
  otherwise answers UNAUTHORIZED before it looks at the mailbox (tracker
  R-9). GET_BUNDLE needs none. First contact is unaffected: the initiator
  authenticates as itself.
- The app: a sync round and `publish_prekeys` make AUTH right after
  connecting, and use that one connection for everything, so every envelope
  it sends goes out on a connection authenticated as its sender;
  `start_session` (GET_BUNDLE only) makes none. The DH is `ArciumCore::identity_dh`, which
  refuses an all-zero output (a low-order auth key), as the relay client
  does too. A failed TLS handshake, a refused AUTH (its text starts
  `network: relay authentication failed:`) and an invalid connection string
  are network errors: the `sync` they happen in ends there, before any bundle
  or envelope is published, read or deleted. The app's round
  (`sync_conversations`) may then open a session with a contact
  (GET_BUNDLE, no AUTH) and call `sync` once more, so one round can try AUTH
  twice; the app's backoff then applies, as after any `network:` error. A
  string with the V2 prefix that does not parse is never tried as
  `host:port`.
- Only the app's Kotlin side refuses V1 in release builds
  (`messaging/RelayRules.kt`, applied when a relay is set and again to the
  saved value at start). The Rust core accepts both versions in every build:
  one release `libarcium_core.so` serves every app variant.

V2 keeps the network from seeing keys and envelopes, keeps strangers from
reading, deleting or replacing a mailbox's contents, and keeps everyone but
the relay's operator from leaving an envelope that names another key as its
sender. It does not hide how full a mailbox is: any key may authenticate and
SEND as itself, and the count of SENDs accepted before FULL is the number of
free places. That tells such a sender how many envelopes wait, and whether
the owner kept or deleted the sender's own messages, not those "from" anyone
else (section 8, R-9). The same shows without filling the mailbox: a SEND of
bytes still stored is answered with their stored sequence number, so the
sender who stored an envelope learns, by sending it again, whether it is
still there, and so when the owner's rounds run. The relay's operator still sees and can delete
everything, and can store an envelope naming any sender.

So below, whoever can put envelopes "from" a contact in a mailbox (a
mailbox writer) is, on V2, the relay's operator, or whoever holds that
contact's identity secret; on V1, in development, it is anyone who reaches
the relay. V2 reuses
the identity X25519 key in one more DH context (the auth key derivation),
separated by its HKDF salt and label; that is not reviewed by a cryptographer
yet.

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
whole answer, ends within 30 s (60 s for a relay at an onion address,
section 3a); a round stops starting requests after 120 s.
Each pass still reads its first page, so a round that ran out moves both
passes on, and the next round continues with what is left.

The price: kept envelopes are read again in both passes of every round, so a
round transfers up to twice the scanned part of the mailbox (at most
2 × 4096 × 64 KiB with the largest envelopes), where a single FETCH read at
most one page. Keeping a round bounded, not cheap, is what this provides.

**Retention.** An envelope stays in the recipient's mailbox until the recipient
deletes it, it is 7 days old, or the relay stops without `--db` (with it, the
mailbox survives restarts; ages are computed from the host's wall clock at
load, so the host needs a correct clock). A mailbox holds at most 4096
envelopes, and all mailboxes together at most 1 GiB of envelopes
(`RelayConfig::max_total_bytes`); a SEND beyond either is refused with FULL,
never made room for. The capacity can be set lower (`--max-mailbox N`,
`RelayConfig::max_mailbox`), never higher: 4096 is what one round's scan
covers (`MAX_SCAN_ENVELOPES`), and `serve` refuses 0 or more than 4096 with
`InvalidInput` before starting anything, so no configuration of this relay
holds entries a round cannot reach. Identical bytes still stored are not
stored twice.

**Delivery does not depend on retention.** The sender keeps every text until
the recipient's receipt arrives, and sends it again after
`retransmit_after_ms`, then after twice as long each time, up to 5 minutes
(section 7). A relay that loses or restarts only delays delivery of
texts, and so does one that withholds them for less than `FAR_SKIP_WAIT`
(below; withholding longer, section 8). Receipts and GONE messages are
never sent again once
the relay has stored them, so losing them leaves gaps in the sender's
chain that nothing fills. A message more than `MAX_SKIP` (1000) positions
ahead of what the recipient read cannot be decrypted as usual; it is
deleted like any message that does not decrypt, and read when it comes
again (a text is sent again; a receipt or GONE message when the text it
answers is). Only for a gap nothing fills is it decrypted with a far
skip, up to `MAX_FAR_SKIP` (100,000) positions per chain (tracker R-14).
A far skip keeps the keys of only the last 1,000 positions it skips, so
it is tried only once the session has seen far messages of that chain for
`FAR_SKIP_WAIT` (10 minutes, twice the longest wait between
retransmissions) without accepting a message, and at the end of a message
pass in which it accepted none: by then a sender that keeps syncing has
sent again every text it still holds, and those that fill the gap are
read first. The wait is kept in the store (below), so a restart of this
device does not start it again. A session tries at most one far skip per sync round, and a
round at most four. A lost message from before the kept keys can never be read; it is
named back in a GONE message when it arrives (section 4), on the current
receiving chain, on one of the last 32 chains left (the chain a far skip
left included) or, on its second arrival, on an older one, unless reaching
it on an older one would need a far skip (section 8). More than 100,000 consecutive lost messages of one sending
chain still stop that direction for good; the way out is a reset of the
session on either device (option B, section 10), which gives up the texts
pending on the old session (`NotDelivered`).

The far-skip wait is the local record `farwait:v1/<handle>`
(`FAR_WAIT_RECORD_V1`, never sent): version (1) = 1, a count (1) of at
most `FAR_CHAINS_PER_SESSION` (4), then per chain the ratchet key a far
message named (32) and when one was first and last seen (8 each,
big-endian milliseconds of this device's clock). It is written when a
chain starts waiting, when its wait starts again, and when its last
sighting moved by a minute or more (the last sighting only orders the
chains for dropping); it is deleted when the session accepts a message,
when the network layer gives the session up (a reset, a restart by the
contact, an own unconfirmed session given up) and, in the same
transaction, with the contact. The exported `remove_session` does not
delete it, which leaves the same as a failed delete (below). The deletes after an accepted message and after a session is
given up are separate writes: a process death just before one, or a
delete that failed (reported in the round's errors when it follows an
accepted message; tried again at the next accepted message), leaves the
record. A far message of a chain it names may then be tried without the
full wait; after a session was given up the record names only that
session's chains, and the next session's first accepted message deletes
it. A record that does not decrypt or parse is read as no wait and
replaced at the next write. If the store cannot be read (or its lock is
poisoned), the session tries no far skip in that round, and the failure
is reported. A write that fails is reported, and the store keeps what it
held (a chain whose start it never took waits again after a restart);
the write is asked for again the next time a far message of that chain
is judged (one per session per pass). The wait is counted by this device's clock, also while the app is not
running (section 8).

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
or prekey secrets, ratchet state or checkpoints. There is no anonymity
towards the relay: it can link sender, recipient and time of every message.
With a relay at an ordinary address, a network observer sees only
connections, their sizes and timing (with V1, in development, it sees the
same as the relay), and the relay sees this device's IP address. With a relay
at an onion address (section 3a), the relay does not learn this device's
address, and an observer of this device's network sees connections to Tor,
not to the relay.

## 3a. A relay at an onion address (Tor)

A relay whose host is an onion name (`*.onion`, in a V2 connection string or,
in development, a V1 `host:port`) is reached only through the Tor client
embedded in the app (arti 0.48, `core-transport`; `mobile-ffi`
`network::tor`), never directly: the name is never handed to this device's
resolver, and no TCP connection is made to it. A relay at any other host is
reached directly, as before. Nothing switches between the two: the address
the user entered decides (decision D-189). Over the Tor stream the protocol is
unchanged: TLS 1.3 to the pinned key, HELLO, AUTH (section 3).

- **One Tor client per process**, started by the first connection to an onion
  relay, which waits for it (`core_transport::BOOTSTRAP_TIMEOUT`, 120 s); a
  connection that comes meanwhile waits for that start. The client then stays
  for the life of the process. A start that fails (no network, a timeout)
  fails that connection; for the next 60 s (`network::tor::RETRY_AFTER`)
  every connection to the onion relay fails at once with the same error, and
  the first one after that starts Tor again. Nothing is tried directly
  meanwhile.
- **Its state** (arti's state and directory cache) lives in `tor/` next to the
  store file: on Android in the app's own files directory, which Android does
  not clear as it may a cache, and which the app excludes from backup and
  device transfer (`data_extraction_rules.xml`).
- **ring** is the process's rustls provider, installed once when an
  `ArciumCore` opens, before any Tor client exists (decision D-193); the relay
  client passes ring to its own TLS configuration in any case.
- **Bounds** (decision D-194, starting values, to be tuned with a real Tor
  network): the stream may take 60 s to open (a rendezvous circuit is built
  first); each request as a whole 60 s instead of 30 s; every read and write
  keeps `timeout_ms`; the TLS handshake and HELLO keep their 30 s; a round
  keeps its 120 s budget, counted from when its connection is open (section
  7), so neither Tor's start nor the wait for the stream uses it up. The
  relay closes a V2 connection whose TLS handshake takes more than 10 s
  (section 3); over a rendezvous circuit that limit is tighter than the
  client's, and may need raising on a relay that serves over Tor (plan step
  4.2). So may its limit of 32 connections per address
  (`max_connections_per_address`): behind its own Tor, such a relay sees
  every client as one local address, so all of them share it. Before a round's first budget check, its connection can take up to
  Tor's start (120 s), the stream (60 s), TLS and HELLO (30 s), AUTH and the
  bundle's PUT (60 s each): about 330 s at worst, against about 100 s for a
  relay at an ordinary address (connect 10 s, TLS and HELLO 30 s, AUTH and
  PUT 30 s each; its name lookup has no bound, tracker R-4).
- **Isolation** (decision D-195): every stream to the relay is in one Tor
  isolation group of its own. Traffic that must not be linked to the
  device's mailbox would need another group.
- **An update the Tor network requires.** When the Tor network lists as
  required a protocol this version of arti lacks, arti 0.48 ends the whole
  process once (`std::process::exit(1)`), from a running client; it has saved
  the requirement in its directory cache before that. Every later start then
  fails at once (`core_transport::TransportError::NeedsUpdate`): connections
  to the onion relay fail with "Tor needs an app update", and
  `tor_state()` is `NeedsUpdate`, until an app update brings an arti that
  implements the protocol. If the cache is lost, the next start can end the
  process once more (decision D-199).
- **`tor_state()`** tells the app whether the process's client is not
  started, starting, running, needs an update, or failed its last start. It
  answers at once, also while Tor starts: it never waits for a start.
- **What the app shows** (Settings, under the saved relay): "Without Tor:
  the relay sees your IP address." for a relay at an ordinary address;
  "Through Tor: the relay does not see your IP address." and Tor's state,
  read every second while Settings is on screen and the app is visible, for
  a relay at an onion address. The app tells the two apart by the core's rule, written again in
  Kotlin (`relayGoesThroughTor` in `RelayRules.kt`, with the core's test
  cases); the core alone decides the route.

What Tor adds and what it does not: the relay does not learn this device's
IP address, an observer of this device's network does not learn which relay
it talks to, and the relay, an onion service, does not show devices where it
runs (running it as one: plan step 4.2, the relay's side). The relay still
sees all it sees in section 3: identity keys, timing, sizes, and which
mailbox a connection reads and sends from.

Not verified here: a real Tor network (no CI job reaches one; the tests use a
stand-in for Tor, `mobile-ffi` `tests::relay_onion`), and Tor on Android
(bootstrap time, data and battery use, arti's check of the permissions of the
app's directory).

## 4. Messages inside the ratchet

`PAYLOAD_V1`, the plaintext of each ratchet message (the wire format is
unchanged; this is only what is encrypted):

| type | content | consumed by |
|---|---|---|
| 1 TEXT | application bytes | the application (`received_texts`, `mark_read`) |
| 2 RECEIPT | 1–256 message ids | the network layer |
| 3 OPEN | nothing | the network layer |
| 4 GONE | 1–256 message ids | the network layer |

OPEN is the initiator's first message. It lets the responder send before the
initiator's first text (a responder has no sending chain until it receives).

GONE names messages of the peer's that arrived after their key was gone, so
they can never be decrypted (tracker R-21): a message that did not decrypt,
whose header names a position behind the next expected one of the
session's current receiving chain, or behind the end of one of the last
32 receiving chains the session left (`MAX_PREV_CHAINS`; one is left per
exchange, so about the last 32 exchanges; the ratchet
keeps each one's peer ratchet key and the position it ended at, the `pn`
of the header that started the next chain), with no skipped key stored for
it (evicted from the full store of 2,000, dropped by a far skip, or used).
A position at or past a left chain's end is not named: the peer sent
nothing there. Once the session has received from the peer, a message
whose header names a chain it no longer knows (neither the current one
nor a remembered one), with no key stored for its position and no far
skip needed to reach it (no more than 1,000 positions into its chain, and
a `pn` no more than 1,000 past the current chain's position), is named
too (Owner, 2026-11-20), on its second arrival: a message of the peer's
next chain decrypts, so a genuine one belongs to a chain left more than
32 exchanges ago, to a time before the session kept a history
(`RATCHET_STATE_V1`), or to another session of the peer (a restart this
device refused, a session given up), and either way it cannot be read
here. A forged header looks the same and is named as well; the peer
changes nothing for an id it has not pending, and a session it gave up
cannot read the GONE. A first arrival is only noted, in memory, up to 256
per session (the least recently seen dropped first; a restart forgets
them, and deleting the contact or giving the session up clears them): a
late text is sent again until it is named, while a GONE is sent until the
relay's acceptance is seen (normally once), so two devices whose sessions
diverged (a rollback, a copied store) do not name each other's GONE
messages round after round; a fault that delivers one twice draws one
GONE more. A message named stays noted, so its next arrival is named
again, as below. Not before the
session received: an initiator's ratchet knows the peer's signed prekey
as its first receiving key, and the contact's first message under a
handshake of its own (a simultaneous start) would look forgotten. The messages found in one
round are named at its end: at most one GONE per session per round, naming
the first 256 of them in id order (the others are found again when the peer
sends them again). A GONE leaves the outbox once the relay accepted it, like
a receipt (section 5); when the peer sends a named message again after
that, a later GONE for the same ids is committed at once, and after that at
most one a minute. The
peer abandons each named id that is a text still pending in its outbox: it
is not sent again and its history entry shows `NotDelivered`, so the user
can send it again. Any other id changes nothing. A message that only looks
late (altered so that it does not decrypt; anyone who saw its header can
make one) is named too, and changes nothing at the peer. Builds before GONE
discard it as an unknown payload.

Client message ids in the outbox: `t || app_id` (texts, app id 1–63 bytes),
`r || message_id [|| round]` (receipts), `o || sha256(handshake)[0..8]`
(OPEN: one per session, so a session that replaces an abandoned one commits
its own; builds before this one used `o` alone), `g || sha256(ids) [|| round]`
(GONE: the round is the minute of a GONE sent again, so the same ids are
named at most once more per minute). `send_message` refuses all of these.

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
  accepted it; so does a GONE message (section 4). If it is lost, the sender
  sends the text again; the recipient receives a duplicate and commits a new
  receipt (at most one per message per minute; a message it can no longer
  read draws a new GONE the same way, section 4). Only a message that was answered when first accepted (a text or
  OPEN) is answered again; a duplicate of a receipt, or of a payload this
  build does not know, is not answered.
- A missing receipt is never read as non-delivery; the text stays pending.
  The recipient can end it only with a GONE message naming its id
  (section 4), which abandons it (`NotDelivered`).
- Neither `acknowledge_outgoing` nor `abandon_outgoing` is exported through
  UniFFI: only this layer takes a text out of the outbox, on a receipt, or
  in `resolve_session_conflict`, on a GONE message naming it (abandoned),
  or when the user deletes the contact
  (`delete_contact`), which marks it abandoned, or for a history entry the
  user cancelled (`cancel_text`, section 10), which is abandoned too.
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
  under (starting with `t`, `r` or `g`, or `o` alone or followed by 8
  bytes). `send_text` and
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
send-id kept)` or `abandoned (abandon_outgoing: a conflict resolution, a
GONE message from the peer, a deleted contact, or a cancel by the user)`.
Repeating `send_text` with the same app id never encrypts again (S2-B2).

Incoming envelope: fetched → `accepted (inbox committed, receipt committed)` →
deleted from the relay → shown → `mark_read (seen)`. A message whose session
does not exist yet stays on the relay until its handshake arrives; it is not
copied, acknowledged or counted as delivered meanwhile, and it does not hide
the envelopes behind it (section 3, reading a mailbox). A message
that does not decrypt, is malformed or comes from an unknown sender is
deleted from the relay and changes nothing; one whose key is gone (on
the current receiving chain or one of the last 32 left; on an older one,
when it arrives again) is also named to the peer in a GONE message
(section 4). A message far ahead in its chain is deleted from
the relay too; once the wait of section 3 is over, the first one of its
session in the pass is also held in memory and tried with a far skip at
the end of the pass.

Handshake: retransmitted by the initiator until the session has received a
message from the peer (its receipt of OPEN). The responder records it as
provisional (a repeat changes nothing; a different handshake for that contact
replaces it, since neither has authority) and creates the session when the
first message authenticates under it. A handshake from a peer it already has
a session with is recorded beside that session (S2-B2 section 4c), under the
same rules and with no more authority: beside an unconfirmed start of this
device's own it raises nothing by itself (section 10, "Conflict"); beside an
established session it may be the peer's restart (section 10, "Reset"). One
this device cannot answer is refused (section 6), except, beside an
established session, a late copy of the handshake that session came from,
which is dropped. No session is replaced automatically: not on
timeouts, not when a peer is offline, not on a handshake alone. A session
is replaced only when the peer's first message under a handshake recorded
beside it authenticates there (option B), which needs the peer's identity
secret or a signed-prekey secret this device still holds (section 8,
"Protection of an established session"), or by the user (`reset_session`, `resolve_session_conflict`,
`delete_contact`). The one
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

**Signed prekey (tracker R-6).** At the start of every round, before the
bundle is published and before anything is read from the mailbox, the
device rotates its signed prekey when that is due
(`ArciumCore::maintain_prekeys`):
- 7 days (`SIGNED_PREKEY_PERIOD_SECS`) or more after the relay first
  accepted it, by this device's clock and in either direction: the old one
  stays as the previous key for one more period, so a handshake built from
  a bundle fetched before the rotation is still answered;
- after the one-time prekey changed since it was made: no previous key is
  kept, since every bundle naming it named a one-time prekey that is gone.

A key the relay never accepted does not age: the round records the relay's
acceptance after its PUT (`note_prekeys_published`), and a round whose PUT
or record fails ends before the mailbox. A handshake is answered under the
current signed prekey, or under the previous one only together with the
one-time prekey it was published with; every write that replaces the
one-time prekey drops the previous key in the same write. A handshake that
names neither is refused as stale (reason 3).

**Refusals.** When a handshake can never be answered (the prekeys it names
were consumed or rotated, and no session holds it), the responder says so.
Typical case: two contacts write to a device for the first time while it is
offline; both handshakes name the one one-time prekey its bundle carried, and
only the first can be accepted.

- When the responder refuses a handshake from a pinned contact with no
  session holding it, with `OneTimePrekeyUnavailable`, `OneTimePrekeyRequired` or
  `StaleSignedPrekey`, it sends `HANDSHAKE_REFUSAL_V1`. The same holds for
  a handshake that arrives beside this device's own unconfirmed session and
  cannot be answered (section 10, "Conflict"), and for one beside an
  established session, except a late copy of the handshake that session
  came from (section 10, "Reset"):

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

  A refusal is sent at most once per contact per 10 minutes, in memory (a
  restart may send one more, and so may a lost answer to a SEND the relay did
  carry out; a second copy names a handshake that is gone by then and is
  dropped). That limit also covers a refused handshake the initiator keeps
  retransmitting: it is refused again once 10 minutes have passed since the
  last refusal to that contact, so a refusal the relay lost after storing it
  (a relay restart without `--db`, a DELETE by the operator, or by anyone on
  V1) is replaced. A first
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
  abandoned, then the session removed (S2-B2 section 6a). It clears a
  conflict flag for that contact (a genuine conflict comes back under the
  new session once the contact's first message authenticates beside it) and
  starts a new session from the contact's current bundle at once. Texts still queued go out in the new one; texts marked
  `NotDelivered` are not sent again (the user can send them again). If the
  new session cannot start then (no bundle, no relay, a crash), the next
  queued text starts it. Each step repeats safely after a crash: the refusal
  stays on the relay until the round deletes it, and once the dead session is
  gone it no longer matches.
- A genuine refusal is final: the responder sends it only where the
  handshake cannot become answerable later (a consumed one-time prekey is
  never reissued; a handshake is refused as stale only when it names
  neither signed prekey held, a previous key never becomes current again,
  and new keys are random). The responder's bundle is published at the
  start of every round, after the round's rotation and before handshakes
  are processed, so the bundle the initiator fetches after a refusal
  usually names the current prekeys. Not always: refusals are sent after the
  round's messages, and one of them (another first message, or a
  confirmation of an own session) can change the one-time prekey again;
  the initiator is then refused again, no sooner than the refusal interval
  allows, and the texts it committed to each refused start read
  `NotDelivered`. Only messages that authenticate as pinned contacts change
  the prekey, so with an honest relay this ends when they stop; a relay
  that keeps serving an old bundle can repeat it, as for first contact.

## 7. Failure handling

Time bounds (`relay::client::REQUEST_DEADLINE`, `network::ROUND_BUDGET`,
`network::RETRANSMIT_CAP`):

For a relay at an onion address, the request bound is 60 s and opening a
connection may take 60 s, plus up to 120 s for Tor's first start (section 3a).

- **One request: 30 s.** Every read, write and flush on the connection waits
  at most `timeout_ms`, and the request as a whole (writing it, reading the
  whole answer) at most 30 s; past that it fails as a lost connection. A relay
  that trickles bytes cannot hold a round open. A page (at most one 1 MiB
  frame) therefore needs a link of about 35 KiB/s to arrive; on a slower link
  a full page of large envelopes cannot be read (no adaptive paging).
- **One round: 120 s of relay requests**, counted from when the round's
  connection is open (and authenticated, on V2). The budget is checked before every
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
| relay restarts mid-round | the round fails; senders retransmit what has no receipt. Without `--db` the relay comes back empty; with it, everything it had answered OK is still there (unless older than the TTL by the wall clock) |
| relay cannot commit a change to its `--db` file (disk full or failing) | that request gets no answer and the connection closes; the round fails as after a lost answer. SEND and DELETE keep failing until the disk is fixed; reads, and publishing an unchanged bundle, keep working |
| DELETE lost | the envelope comes back as a duplicate: no second acceptance, a new receipt |
| crash after a text is committed | the stored bytes are sent after restart |
| crash after acceptance / receipt commit / delete | the inbox holds the message once; its receipt is committed or re-derived from the inbox |
| crash after a receipt is accepted | applied from the inbox at the next sync |
| crash or failure between deleting a far message and its far try (section 3) | that copy is lost: a text is sent again, a receipt or GONE message when the text it answers is; a far message read but not settled is settled from the inbox at the next sync |
| commit outcome unknown | S2-B2 recovery (`recover_session`), which this layer runs itself: at the start of the next round, before it commits a queued text, and when a message for that session is fetched; the envelope stays on the relay |
| the bundle's publication fails (the rotation check, the PUT, or the record of the relay's acceptance) | the round ends before anything is read from the mailbox; the next round publishes again. A rotation committed before the failure stays: its key does not age until the relay has accepted it, and the previous key, which the bundle the relay still serves names, still answers (tracker R-6) |
| crash after a rotation committed, or after the relay accepted the rotated bundle and before that was recorded | the next round publishes the same key and records it; there is no second rotation |
| prekey record unreadable | every round fails at its rotation check, as an export would |
| device clock wrong | a key's age is the difference between two readings of this device's clock: the one when the relay accepted its bundle, and the one of the current round; it rotates when that is 7 days or more, in either direction (section 8, "Clocks"). A steady offset changes nothing; a step of the clock between the two readings moves the next rotation earlier (forward) or later (back), or makes it due at once when the difference reaches 7 days either way; every early rotation drops the older previous key early (a handshake naming it is refused once and made again); a frozen clock stops rotation by time |
| two instances on one database (two processes) | maintenance and the publication record read the prekey record again inside their transaction, so it is created once and rotated once. A first message promoted in one instance while the other rotates or records a publication fails its byte-identical precondition on the prekey record: it is deleted, the handshake is flagged as refused, and its retransmission is answered (under the previous key after a rotation). A promotion in the other instance that commits between this instance's maintenance read and its export (maintenance first reads without a transaction, and the export is a separate read) makes the published bundle pair the current signed prekey with the new one-time prekey: until the next round rotates, a handshake under that pair is answered (so a copy of the store holding the current key could replace a second session, section 8), and one read after that rotation is refused once and made again. Production runs one sync loop; the tests use two instances in one process for creation and rotation only, and none runs this interleaving |
| going back to a build before signed-prekey rotation | not supported: that build cannot read the prekey record (186 bytes), so every round fails at the bundle export; the record is not overwritten |

## 8. Not provided

- Anonymity towards the relay, and metadata protection beyond what Tor hides
  for a relay at an onion address (section 3a). Tor for a relay at an
  ordinary address.
- Authentication of relay clients on V1 (development only): anyone reaching
  such a relay can read (only ciphertext) or delete a mailbox, or replace a
  bundle (refused by the initiator's identity check). On V2 only the owner
  and the relay's operator can. On both, denial of service is possible.
- Refusal feedback beyond the refusal of section 6: a relay can withhold a
  refusal (the initiator then keeps retransmitting, as before refusals
  existed), and a refusal lost after the relay accepted it is sent again
  only when the initiator retransmits the handshake and the per-contact
  limit of section 6 allows it (10 minutes after the last refusal to that
  contact); until then the initiator waits. A refusal queued but not yet
  stored is lost if the responder's process ends.
- Hiding whom a device knows from a mailbox writer and a reader of the
  mailboxes. A refusal of a forged handshake shows a reader that the
  refuser has the named initiator as a contact (it proves it to nobody
  else); so does a message kept rather than deleted (section 3). On V1, in
  development, anyone who reaches the relay reads the mailboxes and can plant
  forged messages and handshakes naming X. On V2 only the relay's operator
  reads them or can plant envelopes naming X (tracker R-9): another sender
  can count the free places in the owner's mailbox (SENDs accepted until
  FULL), but plant only envelopes naming itself, so the count shows only
  whether the owner keeps that sender's own messages: whether it has pinned
  that sender and has no session with it yet, which a real handshake
  shows as well. Counting fills the mailbox, so it is visible and stops
  delivery to its owner until messages are fetched and deleted; sending one
  stored envelope again (section 3) shows the same of that envelope, and
  when the owner's rounds run, without filling it.
- Protection against key-compromise impersonation of refusals. A refusal is
  authenticated by a MAC both parties can make, so whoever holds the
  initiator's identity secret can make one the initiator accepts, and so end
  its pending first contact (its texts become `NotDelivered`) and make it
  start again. That secret already allows impersonating the initiator.
- Automatic resending of texts a refusal, a conflict resolution or a GONE
  message marked `NotDelivered`.
- Naming a late message far into an older receiving chain (tracker R-21):
  a message of a chain the session no longer knows is named in a GONE
  message on its second arrival (section 4), unless reaching it would
  need a far skip (it lies more than 1,000 positions into its chain, or
  its `pn` is more than 1,000 past the current chain's position): it is
  then left to the far-skip path (section 3), where its try fails, and
  its sender keeps sending it until the user cancels it. After a restart
  of this device such a message needs two arrivals again, and a mailbox
  writer who sends 256 or more forged ones of that kind between two
  arrivals pushes its note out. A GONE lost
  after the relay accepted it is named again only when the sender sends
  the message again.
- A bound on GONE messages sent again. A sender that does not act on a GONE
  (a build before GONE, or a pending message that is not a text) keeps
  sending the message, and each repeat draws a later GONE, at most one a
  minute per set of ids, each leaving a send-id record: as a repeated text
  draws a receipt (section 5, tracker R-12).
- Naming against a mailbox writer. Whoever can put envelopes in the
  mailbox (section 3: on V2 the relay's operator or whoever holds the
  contact's identity secret; anyone on V1) can fill the 256 places of each
  round's GONE with ids of messages of its own, so that a genuine late
  message is never named: a header of a key the session does not know,
  sent twice, is enough (or 256 of them sent once, between two arrivals of
  a genuine message of a forgotten chain), no header of the session needs
  to be seen. A
  relay can as well withhold the GONE. Its length shows a reader of the
  mailbox how many ids it names, so how many late messages were found.
  Such a message draws a GONE only from a session that has received from
  the contact, so the writer also learns that this device has one: an
  answer that depends on whom the owner pinned and talks to, next to
  tracker R-9, accepted with this rule (Owner, 2026-11-20). On V2 the
  relay's operator sees the session's envelopes anyway.
- One provisional handshake per contact. A mailbox writer (section 3: on V2
  the relay's operator, on V1 anyone) can keep replacing a
  contact's recorded handshake before its first message arrives; the genuine
  one is then
  retransmitted and takes over. Since option B this also holds beside an
  established session, where a record stays until the session is retired:
  a writer can delay a genuine restart this way, and every message that
  fails to decrypt on such a session costs one X3DH and one first-message
  trial. That delays first contact; it creates no
  session and consumes no prekey. Each such first message costs the responder
  one X3DH and one ratchet step. The same holds for the handshake recorded
  beside a device's own unconfirmed session (section 10, "Conflict"):
  replacing it keeps a genuine first message from authenticating, which
  delays the conflict being shown, as withholding envelopes does; and each
  message from the contact that does not decrypt under that session costs
  one X3DH and one ratchet step more (including up to `MAX_SKIP` (1000)
  skipped-key derivations, which a forged header can ask for), under the
  store lock. It is bounded by what the sender can store in the mailbox; it
  was not measured. A beside record that cannot be read counts as none: the
  check is reported and the message deleted, and the round goes on.
- Free far skips. A message of an existing session more than `MAX_SKIP`
  (1000) positions ahead in its chain is decrypted with a far skip, which
  derives up to `MAX_FAR_SKIP` (100,000) chain keys for each chain it
  crosses before the message authenticates, under the store lock: about
  47 ms for one chain and 88 ms for two in a release build on one 2.1 GHz
  Xeon core (phones not measured). A session tries one only after
  `FAR_SKIP_WAIT` without accepting a message (section 3), one per sync
  round, and a round at most four (`FAR_TRIES_PER_ROUND`;
  `sync_conversations` may run two rounds). A far message without a try is
  deleted, as one that does not decrypt is, so nothing is kept for a
  reader of the mailbox to count (tracker R-9). A mailbox writer (section
  3) can make forged far messages: no header of the session is
  needed, a key it never saw and a position past 1,000 are enough. One
  costs a try once its own chain's wait is over, and one ahead of a
  genuine far message takes that session's try; four "from" four contacts
  take the round's. For as long as the writer keeps doing it, a genuine
  far message is not read: a denial of service, as filling the mailbox is.
  The wait is kept per chain, so such a forgery starts no genuine chain's
  wait; one naming the genuine chain's key (its header is visible to the
  relay's operator, and to anyone on V1) does, and the genuine chain may
  then be skipped to without waiting. Forgeries can also hold a far skip
  back: one ahead of each genuine far message takes the session's single
  judgement in that pass, and four keys of their own judged between two
  passes in which the genuine chain is judged drop its wait, which then
  starts again (`FAR_CHAINS_PER_SESSION`). For as long as the writer keeps
  doing it, and for up to `FAR_SKIP_WAIT` after it stops, the far skip
  does not happen. And a far try takes tens of
  milliseconds where a message that does not decrypt takes microseconds,
  so whoever can time the round may tell a contact with a session from a
  stranger (next to tracker R-9). The first far message of a chain also
  costs a store write in that round (`farwait:v1`, section 3; the same
  chain again at most once a minute, unless its previous write failed), which a far message "from" a
  stranger does not, so a mailbox writer can see the same in the first
  round, without waiting.
- Delivery against a relay that withholds for longer than `FAR_SKIP_WAIT`.
  A relay that withholds the start of a run of more than 1,000 texts (on
  each retransmission) while passing the later ones makes this device
  skip to them after the wait: the withheld texts can no longer be read.
  Those that arrive are named back and read `NotDelivered` (section 4), so
  their sender can send them again, except, once the chain the skip left
  is no longer among the last 32, those whose reaching would need a far
  skip (more than 1,000 positions into it, or a `pn` more than 1,000 past
  the current chain's position), which stay pending until the user
  cancels them. The relay cannot tell this device
  apart from one whose gap nothing fills; before far skips, it could stop
  that direction for good instead.
- A far-skip wait independent of this device's clock (tracker R-14). The
  wait is stored (section 3) and read from this device's wall clock, as
  the Owner chose on 2026-11-19: a far skip is due once the clock reads
  `FAR_SKIP_WAIT` or more after the chain's first sighting, and a reading
  earlier than that sighting makes it the first sighting again. So the
  wait goes on across restarts and while the app is not running: after
  an absence of `FAR_SKIP_WAIT` or more, the first round may try the far
  skip, unless that pass accepts a message of the session. A step of the
  clock forward between two readings shortens the wait (also a clock set
  back before the first sighting and then corrected), so a far skip may
  come before the sender has sent again what it holds (what is skipped
  then is lost as above); a step back that stays after the first
  sighting lengthens it; a clock frozen, or held back by an attacker,
  holds the far skip back for as long as it stays so. Before, the wait
  was in memory and a device whose process never lived `FAR_SKIP_WAIT`
  kept waiting.
- Naming a message lost before a far skip's kept keys on a chain the skip
  left (tracker R-14): the skip to `pn` drops up to about 99,000 positions
  of the chain being left. A lost text from there is named in a GONE
  message like any late message of a chain left (section 4) while that
  chain is among the last 32 left (a header of such a chain never takes
  a far try), and after that too, on its second arrival, unless reaching
  it would need a far skip (more than 1,000 positions into its chain, or
  a `pn` that far past the current chain's position): then it may cost a
  far try, which fails, and its sender keeps sending it until the user
  cancels it.
- A far skip for a sender that is not sending. The wait assumes the sender
  syncs while far messages arrive, so that it sends again what fills a
  gap. A text the sender holds but has not sent again within
  `FAR_SKIP_WAIT` of the first far message, while this device accepted
  nothing from it, is lost to a far skip; it is named back and reads
  `NotDelivered` when it arrives later (section 4), unless reaching it on
  a chain the session no longer knows would need a far skip.
- A second initiator racing for the same one-time prekey is refused and
  starts again (section 6). With k contacts racing, the k-th may wait up to
  about 10 minutes per further refusal (the per-contact limit).
- A one-time prekey kept across a confirmation. Every confirmation of this
  device's own session replaces its one-time prekey (section 10,
  "Conflict"), and the previous signed prekey with it (the next round then
  rotates the signed prekey, tracker R-6), so another contact whose first
  contact under it is in flight
  is refused and starts again, and the texts it had committed read
  `NotDelivered` for its user to send again; so is a contact's restart in
  flight ("Reset"). At most once per confirmation of an own session.
- Protection of an established session after a key compromise (option B).
  A restart is authenticated by X3DH alone, so two secrets each suffice to
  replace an established session and then read and write it as the
  contact: the contact's identity secret, and a signed-prekey secret this
  device still holds (key-compromise impersonation, which also makes a
  first contact or a conflict "from" any pinned contact; with it, X3DH's
  first DH, `DH(signed prekey, contact's identity key)`, needs no secret of
  the contact). Its holder must also put envelopes in the mailbox as the
  contact (on V2 the relay's operator; on V1 anyone who reaches the relay;
  with the contact's secret, anyone). The signed prekey is rotated (tracker
  R-6, "Rotation of the signed prekey" below), so a copy of this device's
  store works this way only until the key it holds is gone:
  - at the first round after the one-time prekey changed (a first contact
    accepted, a confirmation of an own session, the replacement of option B,
    or the holder's own accepted forgery);
  - at the latest about two periods (14 days by this device's clock) after
    the relay accepted that key, counting only rounds that publish their
    bundle. A key ages only once the relay has accepted it, so a relay that
    refuses or cuts the bundle's publication delays this (the copied key is
    not removed while its successor is unaccepted) for as long as it does
    so; meanwhile every round of the device fails before it reads the
    mailbox, so the device processes nothing and shows the relay errors.

  Within that time, with one instance on the database, a copy allows at
  most one session replacement or first contact: the one accepted consumes
  the one-time prekey and the previous key in the same write, and the next
  round rotates before a new one-time prekey is published. (With two
  instances, a promotion in one can be published by the other before it
  rotates, section 7.) A conflict beside an own unconfirmed session can
  still be raised meanwhile, more than once (that check only reads). Not bounded:
  - the identity secret is in the same store, and its holder can sign
    signed prekeys of its own, impersonate this device to its contacts and
    restart its sessions there, for as long as the identity is used;
  - malware with lasting access gets every new key;
  - a rollback of the store (S2-B2 section 8, D-009) brings old keys back
    until they are rotated out; a restored key due by time stays about one
    more period as the previous key.

  Before option B such a compromise could not replace an existing session,
  and the Double Ratchet's fresh DH steps ended the reach of a stolen
  session state; within that window healing no longer bounds it. The only
  sign is `peer_reset` ("the contact restarted the secure session"), the
  same notice as a genuine restart. Confirmed at runtime:
  `tests::spk_rotation::a_copied_store_cannot_replace_a_session_once_its_signed_prekey_is_gone`,
  `a_copied_store_replaces_at_most_one_session`.
- Restarts and the relay. A relay that withholds the first message of a
  restart keeps the contact's device on the old session, which the
  restarting device can no longer read; texts wait until the relay passes
  it, as when it withholds anything else (once the one-time prekey it names
  has changed, or the signed prekey it names is no longer held, the
  restart is refused and made again). A store written
  before option B did not replace its one-time prekey when its own session
  was confirmed, so a genuine handshake of the contact built from it, which
  this device never saw (the operator withheld it during a simultaneous
  start the contact then gave up), could later replace the established
  session with one the contact no longer holds. The first round of a build
  with option B on such a store replaces the one-time prekey once
  (`ArciumCore::replace_prekey_once`), which closes that; another contact's
  first contact in flight under the old prekey is refused once and starts
  again.
- Rotation of the signed prekey (tracker R-6). At the start of every round
  (section 6, "Signed prekey"): 7 days after the relay first accepted it,
  with the old one kept as the previous key for one more period; and at the
  first round after the one-time prekey changed, without a previous key.
  The previous key answers only together with the one-time prekey it was
  published with. Every answered handshake uses a one-time prekey (tracker
  X-6), which is replaced when a first message under it is accepted, and
  whenever this device's own session is confirmed (section 10,
  "Conflict"). After that, the identity, the signed prekeys and the prekey
  record this device keeps do not derive the keys of a first message under
  it. Before it, they do, but only while the signed prekey it names is
  still held, at most about two periods of rounds that publish the bundle
  (see "Protection of an established session" above): whoever later takes this device's
  store, and holds a copy of the messages (the relay's operator can keep
  one), can read the first messages of handshakes built from bundles that
  name keys in the copy, without being seen. Those are the next first
  contact under the one-time prekey held then, and the first messages of a
  handshake never accepted here while its one-time prekey stays published
  (one the relay withheld, one from a contact deleted before it arrived or
  while a conflict with it was shown, one beside a session this device
  gave up whose contact never sent it again). Later bundles name a signed
  prekey the copy lacks. What remains:
  - whoever holds the identity secret can sign a signed prekey of their
    own, which rotation does not stop;
  - the plaintext of messages read here stays in the history and inbox,
    which a leak of the store exposes anyway;
  - a replaced secret is dropped and wiped in memory (x25519-dalek wipes a
    `StaticSecret` on drop: read from its source, not observed on a device,
    H-8), and moves of secrets can leave stack copies (H-7);
  - on disk the record is rewritten in place with SQLite's `secure_delete`
    on; whether that overwrites the old cell on an update is not shown
    (the F-10 test covers a delete), and the rollback journal is unlinked,
    not overwritten, so old encrypted pages may stay on flash;
  - a responder session an older build stored at generation 0 (S2-B2
    section 4b) keeps a copy of the signed prekey of its time in its
    ratchet until its first message; it no longer answers a handshake,
    since the prekey record decides that.

  The cost: an initiator delayed by more than about one period between
  fetching the bundle and this device reading its handshake, or a conflict
  left unresolved that long, is refused and starts again, and its committed
  texts read `NotDelivered`.
- Clocks (tracker R-6). The age of a signed prekey is read from this
  device's clock, which is accepted and documented (Owner, 2026-11-19; to
  be reconsidered at the security audit). The age is the difference
  between two readings of that clock: the one of the round in which the
  relay accepted the key's bundle, and the one of the current round. The
  key rotates when the difference is 7 days or more, in either direction
  (`plan_rotation`). So:
  - a steady offset has no effect;
  - a step of the clock between the two readings moves the next rotation:
    earlier for a step forward, later for a step back; and it is due at
    once when the difference reaches 7 days either way (a clock that was
    behind when the key was published and is then set right counts as a
    step forward);
  - every early rotation, forward or back, drops the older previous key
    early, so a handshake naming it is refused once and made again;
  - a frozen clock, or one an attacker holds, stops rotation by time,
    which is no worse than before rotation existed, while a change of the
    one-time prekey still rotates an active device;
  - a clock that jumps by a period every round rotates every round, so
    first contacts keep being refused; that needs control of the clock,
    and an attacker in the network path can block the relay anyway.
- The bundle changes about once a week while the device is online (tracker
  R-6): a rotation by time publishes a new signed prekey, and `GET_BUNDLE`
  needs no authentication. Whoever can fetch the bundle (anyone who knows
  the device's key) can poll it and learn roughly when the device ran its
  first round after each 7-day mark, for example when it came back after a
  long absence. A change of the one-time prekey already changed the bundle
  before rotation existed.
- Simultaneous initiation: if both users start a session with each other
  before either handshake arrives, each device holds an unconfirmed initiator
  session and records the other's handshake beside it, so neither proceeds
  (no fork: each side's messages fail to decrypt at the other and write
  nothing). Nothing resolves it automatically. The conflict is recorded and
  shown once the other side's first message authenticates under its
  handshake, and the user of one device resolves it (section 10).
- Protection against a replayed conflict (the residual of tracker R-13). A
  forged handshake or first message raises no conflict any more. A genuine
  handshake and first message replayed later still do, if this device never
  accepted that handshake and can still answer it: the one-time prekey it
  names is still the published one, and the signed prekey it names still
  held, at most about two periods of rounds that publish the bundle
  (tracker R-6; S2-B2 section 4c). Whoever reads this
  device's mailbox on the relay can capture them: on V2 the relay's
  operator, on V1 anyone who reaches the relay. A dead end needs more than
  the replay: the contact must have given that session up without this device (for
  example it deleted and re-added this contact), this device's own session
  must still be unconfirmed, every message of the contact under this
  device's session must be withheld until the user resolves, and the user
  must resolve. Once the contact accepts this device's session and its
  receipt arrives, the conflict clears by itself. The way out of a dead
  end is a reset on the waiting device, or deleting the contact on both
  devices (section 10). A handshake
  that created a session here cannot be replayed this way: its one-time
  prekey was consumed and replaced.
- Read receipts; multi-device; group messaging; attachments.
- Protection against a full mailbox. Paging (section 3) only stops kept
  envelopes from hiding later ones. Anyone who can reach the relay can still
  fill a mailbox to its 4096 entries (SEND is then refused; on V2 by
  authenticating as any key of its own); on V1 anyone can
  also delete from it, on V2 only its owner and the operator. A full mailbox stops delivery to its owner only: a sender's round goes
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
| `NotDelivered` | given up after a conflict resolution, or named by the peer in a GONE message (it arrived after its key was gone); the peer never accepts it |
| `Cancelled` | given up by the user (`cancel_text`); no longer sent, and a copy the relay already accepted may still be accepted by the peer |
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
  unconfirmed start of our own raises nothing by itself: its bytes are
  public, so a mailbox writer (section 3) can send one "from" the contact
  (tracker R-13). It
  is checked against this device's prekeys and recorded beside our session
  (S2-B2 section 4c), replacing one recorded before. The conflict is
  recorded when a message from the contact that does not decrypt under our
  session authenticates as the contact's first message under that
  handshake, which needs the contact's identity secret or a signed-prekey secret this device still holds (section 8, "Protection of an established session"). Nothing is stored
  for that message, and it is deleted from the relay like any message that
  does not decrypt here: the contact keeps it in its outbox and
  retransmits it, with its handshake, until our receipt (which no session
  here can give) or until it gives that session up itself. So it is still
  being sent when it can be accepted, which is only after our session was
  removed. A handshake that cannot be answered here (its one-time prekey
  was consumed, or its signed prekey is neither the current nor the
  previous one) raises nothing
  either; it is refused as section 6 describes, so a genuine contact gives
  that session up and starts again, and a refusal elicited by a forged one
  names no handshake the contact holds and is dropped there. Builds before
  this change recorded the conflict on a handshake alone; that stored flag
  is no longer read, so a false conflict such a build recorded is neither
  shown nor resolvable, and a genuine one is recorded again from the
  contact's retransmitted first message. (A dead end such a build reached
  by resolving a false conflict stays until a reset on the waiting device,
  or deleting the contact on both devices.)
  Only the device with the greater identity key may resolve it
  (`resolve_session_conflict`), and only when its user asks. That device marks
  its committed texts `NotDelivered`, abandons them, removes its unconfirmed
  session (allowed by S2-B2 section 6a: nothing was received on it), and waits
  for the contact's handshake, which the contact retransmits. The user can
  send those texts again as new messages. Nothing is removed automatically.
  A text committed concurrently, between the marking and the abandoning, is
  abandoned too and shown `NotDelivered` from its record; one committed after
  the abandoning makes the removal refuse (`PendingOutgoing`), and calling
  again completes it.
  A forged handshake or first message can no longer raise a conflict. A
  replay can still raise a false one: a genuine handshake and first message
  of a session the contact has since given up, captured from the relay,
  which this device never accepted and can still answer (section 8).
  Resolving a false conflict is not harmless. If the contact goes on to
  accept this device's
  original handshake, the two devices dead-end: this device waits for a
  handshake that never comes, and the contact keeps an established session
  whose messages this device cannot read. Nothing resolves that
  automatically; the way out is a reset on this device ("Reset", below),
  or deleting the contact on both devices (tracker R-13; options in
  `docs/SESSION-RECOVERY-OPTIONS.md`). On the
  device with the smaller key, a false conflict clears by itself once the
  contact confirms the session.
  When a message from the contact confirms this device's own session, the
  handshake recorded beside it is discarded, and in the same transaction
  this device's one-time prekey is replaced (tracker R-6, option B): a
  first message of the contact under that handshake may have
  authenticated here, read with the prekey, and the contact gave that
  session up; and a handshake of the contact this device never saw,
  replayed later, must not replace the established session ("Reset",
  below). Another contact's handshake that names the replaced prekey is
  refused and starts again, as when a first message consumed it (section
  6).
- **Reset.** `reset_session(peer)`, on the user's request, starts the
  secure session again (option B; Owner decision 2026-11-18: only the user
  starts it). It works without a connection, in any session state but a
  conflict (resolve that instead), also with no session (the dead end after
  resolving a false conflict, `AwaitingPeerSession`). A commit whose
  outcome is unknown is settled first. A session record that cannot be read
  is refused with nothing changed (delete the contact instead, option C).
  The contact's device must run a build with option B: an earlier build
  drops a handshake beside an established session, so the resetting device
  waits until the contact updates (or both delete each other and exchange
  cards again). The update replaces the contact's one-time prekey once, so
  the waiting restart is refused and made again: the texts the resetting
  user wrote while waiting read `NotDelivered` and must be sent again, as
  must the contact's texts on the old session. The texts committed to the current
  session, also one committed by a send on another thread while the reset
  runs, are marked `NotDelivered` and abandoned, the
  session is removed (S2-B2 section 6a, `retire_session`), and the next
  round starts a new session from the contact's current bundle, also with
  no text queued. The contact's device records the new handshake beside
  its established session; when the first message under it (the OPEN that
  goes with every handshake) authenticates there, the contact's device
  marks its own texts committed to the old session `NotDelivered` (a text
  whose receipt it read earlier in the same round reads `Delivered`),
  abandons them, removes that session and accepts the new one, all before
  deleting the message from the relay, so a crash at any step repeats it.
  The notice below is written in the transaction that removes the session,
  and on the resetting device so is its request to start again, so a crash
  cannot leave the old session gone and no new one coming. A text the
  contact sent on the old session that arrives in the same round as the
  restart can enter the history after a text of the new session (only the
  order differs). Its
  conversation then shows `peer_reset` ("the contact restarted the secure
  session") until its user sends a text or resets. A handshake alone, a
  forged first message, or a replay of a handshake older than the session
  replaces nothing (its one-time prekey was replaced when the session was
  confirmed, above). A restart the contact's device can no longer answer
  when it arrives (the one-time prekey it names was consumed by another
  first contact, or replaced at a confirmation, since the bundle was
  fetched, or the signed prekey it names was rotated out, about a period
  or more after the fetch, tracker R-6) is refused there, as in section 6, and the restarting device
  makes it again from the current bundle (`restart_after_refusal`); texts
  it had committed to the refused start read `NotDelivered`. A late copy
  of the handshake the contact's own responder session came from is never
  refused: its initiator retransmits it until the receipt arrives, and a
  refusal would end the session it just made. The responder device records
  which handshake that was (S2-B2 section 4c, `hsacc:`), by the keys it
  derives rather than its bytes, so a relay that replaced the initiator's
  ephemeral key with another encoding of the same keys before the
  responder read it gains nothing (second review of option B). For a
  responder session stored by an older build there is no record, and such
  a copy is refused, which ends the initiator's session only if the responder's
  receipt has not reached it yet (the restart that follows replaces it on
  both). When both users reset before either new handshake
  arrives, each device holds a new unconfirmed session and the other's
  handshake beside it: the conflict above, resolved as above (Owner
  decision). What either side sent on the old session after the other gave
  it up cannot be read and reads `NotDelivered` once given up there; a text
  given up at a reset may still have been read by the contact before it
  restarted, so `NotDelivered` here means "given up", not "never read".
- **Deleting a contact.** `delete_contact(peer)`, on the user's request,
  removes in one store transaction the pinned card, the name and flags, the
  whole history, and the session in any state (established, unconfirmed, in
  conflict, unreadable or absent) with its handshakes, pending outgoing
  texts and pending incoming messages (S2-B2 section 6a, "Forgetting a
  peer"). Pending texts are marked abandoned there, so none is ever read as
  delivered; the `seen:` and `sendid:` records stay, so nothing is
  encrypted twice and nothing already received is new again. Undelivered
  texts are lost, and the contact is told nothing: it keeps its session,
  and a new handshake from this device is recorded beside it. If this
  device adds the contact again and sends a text, the first message of
  the new session replaces the contact's session there, as a reset does
  ("Reset", above), if the contact runs a build with option B. Both users
  can also delete each other and exchange cards again; the next text then
  starts a new session, with any build. Deleting again, or deleting someone who is not a contact, is
  harmless. Every chat record is written in a transaction that first finds
  the card still pinned, so a call that read the contact before the delete
  writes nothing for it after (a user action then fails as for any
  non-contact), and a re-added contact inherits no history or flag.
- **Cancelling a text.** `cancel_text(peer, app_id)`, on the user's request,
  gives up on an own text not yet final (`Queued`, `Pending` or
  `Transmitted`; tracker R-15). It marks the entry `Cancelled` in one
  transaction (which also takes it off `chat-open`), then abandons the
  committed message, if any: it leaves the outbox and its send record reads
  abandoned, so the same id is never encrypted again. Marking first means a
  `refresh` never reads that abandonment as `NotDelivered`. From the mark
  on, `publish_pending` never sends the text: before sending each text it
  reads its entry, and abandons a `Cancelled` one instead. This covers a
  cancel cut by a crash between the two steps, and a text another thread
  commits after reading the entry as `Queued` before the mark. A round
  already past that check may send it once more; the Android app cancels on
  its sync thread, between rounds. An error after the mark leaves the entry
  `Cancelled` and the text unsent; calling again completes it.
  `Cancelled` claims nothing about the peer: a copy the relay already
  accepted may still reach it and be accepted there, and its receipt then
  finds the message abandoned, so the entry stays `Cancelled`. If the
  receipt was taken before the cancel (also one that lands while the
  cancel runs), the entry reads `Delivered` (`Cancelled` → `Delivered` is
  the one move out of `Cancelled`). A crash inside a cancel that a receipt
  races can leave such an entry `Cancelled`. A final
  text is returned as it stands, and repeating a cancel is harmless. The
  user can send the text again, as a new message with a new id. The
  peer is told nothing. This device never gives up by itself: a text the
  user does not cancel is retransmitted for as long as the app runs, unless
  the peer names it in a GONE message (section 4).
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
  `Transmitted`; not `Cancelled`). It changes in the transaction of every entry change that
  adds or removes one. Rounds, sends and the giving up of a session walk it
  instead of the history. A history written before it existed has none; it
  is built once, in one transaction, from the entries. The conversation list
  reads the last entry and the entries not yet seen, not the history.
  Listing a store namespace (the outbox, the inbox, the contacts) is still a
  scan of the whole SQLite table on every call (`list_keys_with_prefix`), so
  a round keeps a cost that grows with the store's size; it no longer
  decrypts the history.
- **Not provided.** Push delivery: nothing wakes the application when a
  message reaches the relay (no FCM or other push service). Sync while the
  application is closed exists on Android only as an opt-in foreground
  service, off by default, that runs the open app's rounds and stops with
  the app's process; it does not start after a reboot (`android/README.md`,
  "Background receive"). Unread state across devices; a sender timestamp
  (entries carry the local time they were recorded). The conversation
  screen reads a window of the newest entries
  through `chat_entries_page` and widens it by 50 on "load earlier"
  (`loadWindow` in `android/.../ui/chat/ChatViewModel.kt`), so it no longer
  reads the whole history.

## 9. Verification

| property | test | evidence class |
|---|---|---|
| first contact, identity binding, stranger drop | `tests::network` V1 tests | runtime, local relay over TCP |
| the V2 relay stores a SEND only from a connection authenticated as the envelope's sender: none without AUTH, none naming another key or too short to name one, none after a wrong AUTH, and a refused SEND is answered UNAUTHORIZED, not FULL (tracker R-9) | `relay` `v2_tests::a_send_is_stored_only_for_an_envelope_naming_the_authenticated_owner`, `v2_tests::without_auth_only_get_bundle_is_answered` | runtime, local V2 relay over TLS |
| the app over a V2 relay: first contact, texts both ways, receipts; neither a connection without AUTH nor a third device (as itself, or claiming the owner's key) can read, delete or publish another device's mailbox or bundle (the reading half of R-9; how full a mailbox is stays visible); a forged message or handshake naming a pinned contact is refused by the relay, with or without the forger's own AUTH, and only the forger's own envelope is stored (R-9); a wrong TLS pin, a refused AUTH, a low-order auth key and a malformed connection string end the round with a network error and change nothing on the relay; a malformed V2 string is never tried as V1 | `tests::relay_v2` | runtime, local V2 relay over TLS |
| which relay a build accepts: V2 strings everywhere, `host:port` in debug builds only | `RelayRulesTest` (Android JVM unit test) | unit |
| a handshake alone is not a session; its first message creates it; a recorded handshake does not block simultaneous initiation | `tests::responder` | runtime, local relay over TCP |
| both directions, restarts, consistent histories | `both_directions_and_both_histories_survive_restarts` | runtime |
| offline recipient | `messages_to_an_offline_recipient_wait_on_the_relay` | runtime |
| kept envelopes never hide later ones: prefixes of 0–4095 entries, large envelopes, handshakes behind or after the prefix, mixed kept and deleted, deletes, appends and expiry between pages, a mailbox that never runs dry, a relay that breaks paging, lost answers, a stopped relay, process death between pages | `tests::mailbox_scan`; relay paging and the refusal of a capacity above 4096 in `crates/relay` tests | runtime, local relay over TCP; process crash |
| relay outage; broken SEND/FETCH/DELETE/receipt | `a_relay_outage…`, `broken_connections_at_each_step…` (TCP proxy) | runtime; faults injected at the socket |
| one recipient's full mailbox: the round goes on for everyone else, the wait and its doubling, order of the waiting texts, a refused receipt | `tests::send_refusal` | runtime, local relay holding 8 envelopes per mailbox; waits scaled down |
| process death at each boundary | `tests::network_crash` (child `abort()`) | process crash |
| request deadline against a trickling relay; round budget on a slow relay with every text received once; a cut round continuing past a page of kept envelopes; backoff to the cap | `tests::net_limits`, `relay` client tests | runtime, local sockets; time scaled down in tests |
| replay, reorder, malformed, forged and cross-session receipts, replayed handshake, lost receipt, a replayed receipt not answered | `tests::network` V6 tests | runtime |
| what a device keeps after it accepts a first contact (identity, signed prekey, prekey record) does not decrypt its first message again, and the session no longer uses the signed prekey; every confirmation of an own session replaces the one-time prekey in the confirming transaction, and nothing else does, and nothing is written if a record the replacement read changed before the commit (tracker R-6) | `what_a_device_keeps_after_a_first_contact_does_not_read_it_again`, `a_one_time_prekey_read_beside_a_session_that_wins_is_replaced`, `a_confirmation_of_an_own_session_replaces_the_prekey_and_nothing_else_does`; `core_protocol` `messaging::tests::beside`; the conflict test of `tests::chat` | runtime, in process; local relay over TCP |
| signed-prekey rotation (tracker R-6): rotation at the start of a round, before the mailbox is read; no handshake read in a round whose PUT or whose record of the relay's acceptance failed (a rotation committed before the failure stays); a handshake built before one rotation answered under the previous key, one two rotations later refused (reason 3) and made again, its text `NotDelivered`; a restart under the previous key replacing the session and one past its grace refused and made again; a rotation whose publication failed still answering the bundle the relay kept serving after any absence; a late copy of the accepted handshake not refused after rotation; a copied store replacing a session only while its signed prekey is held, and at most once (also under its previous key); a store from an older build rotated at its first round, with and without the mark of option B; process deaths after the rotation and after the PUT rotating once; the rule ((E), (T) in both clock directions for keys of different ages, an unpublished key never aging), the record (V3, V2 read, strict parsing), every one-time-prekey writer dropping the previous key, the previous key answering only with its one-time prekey (also beside a session), two instances on one database creating and rotating once while the other holds its transaction | `tests::spk_rotation`, `tests::prekey_record`, `tests::legacy_upgrade::a_v2_prekey_record_is_rotated_on_the_first_round`, `tests::network_crash::a_device_killed_around_a_rotation_rotates_once_and_answers_the_served_bundle` | runtime, local relay over TCP; real process deaths; unit; two instances on one database stand in for two processes; device clocks not tested |
| a reset replaces the session on both devices (texts committed to the old one `NotDelivered` on each, the contact told), also when an old-session text arrives in the same round, and ends the dead end of a false conflict; a restart whose one-time prekey another first contact consumed, or a confirmation replaced, is refused and made again; a late copy of the handshake a session came from is not refused, also when the relay replaced its ephemeral key with another encoding of the same keys; an unreadable `hsacc:` record stops no round and is written again; a receipt read in the round of a restart still delivers; a reset of an unreadable session changes nothing; a store from before option B replaces its one-time prekey once; a text sent while a reset gives the session up is given up with it; a forged restart and a replay of a handshake older than the session replace nothing; both users resetting at once is the conflict, resolved by the greater key; reset rules; process death at each new step on both devices (option B) | `tests::restart`; `tests::a_handshake_is_known_in_every_encoding_of_its_keys`; `core_protocol` `messaging::tests::beside::a_handshake_beside_an_established_session_is_kept_until_the_session_is_retired` | runtime, local relay over TCP; process crash |
| a gap of more than `MAX_SKIP` in one chain (texts given up after they were encrypted, or lost on the relay) is crossed with a far skip and both directions go on; a far skip only after the wait without accepting a message and not in a pass that accepted one; a rotated mailbox and a lost start sent again later deliver every text; one far try per session per round, a far message without a try deleted and read when sent again, nothing kept on the relay; at most four tries per round over six sessions; the wait kept per chain (a forged key starts no genuine wait), counted from the chain's first arrival, the chain seen least recently dropped first, a session judged once per pass also when the round is full, and the waits forgotten when the contact is deleted; the wait kept in the store across a restart, deleted once a message is accepted, with the contact and on a reset; the record's layout and strict parsing, a record that does not parse read as none and replaced, a clock set back before a chain's first sighting starting its wait again, the last sighting stored at most once a minute (counted) while dropping follows the exact one, a write that failed asked for again (unit, sightings only); a far try that fails other than by not decrypting, and a message read with one that fails to settle, each reported with the pass going on; a lost text from before the kept keys of the current chain named back in a GONE message; in the ratchet, the gap in the current chain, in the chain being left and in both at once, the last `MAX_SKIP` keys kept, `MAX_FAR_SKIP` and no further, a forged far message changing nothing, no key left behind, no far skip past `MAX_RESUMABLE_NR` | `tests::far_skip`; `network::tests` (the far-wait record and sightings); `core_crypto::ratchet` (`a_far_skip_*`, `a_forged_far_message_changes_nothing`, `a_stored_key_needs_no_far_skip`, `no_temporary_key_outlives_a_far_skip`), `ratchet::checkpoint` (`a_far_skip_never_moves_nr_past_the_resumable_limit`) | runtime, local relay over TCP; unit |
| a message whose key was evicted is named back in a GONE message and the text is abandoned (`NotDelivered` in the history), also when it arrives after the ratchet turned, on a chain the recipient left (the last 32 are remembered, from `RATCHET_STATE_V2`) or no longer knows (33 turns later, on its second arrival; not before the session received from the contact, not a far message in its wait; at most 256 first arrivals noted per session, the oldest pushed out); a GONE lost on the relay is sent again when the text is repeated, not again within the minute, and once more a minute later (the minute set by a test aid); ids the sender has not pending as a text (unknown, delivered, not a text) change nothing; altered copies that only look late draw one GONE per round; a failed round keeps nothing to name | `tests::beyond_recall`, `tests::far_skip::a_far_message_in_its_wait_draws_no_gone`; `core_crypto::ratchet` (`a_position_whose_key_is_gone_is_beyond_recall`, `a_late_message_of_an_earlier_chain_whose_key_is_gone_is_beyond_recall`, `a_header_of_a_forgotten_chain_is_named`, `a_checkpoint_written_by_the_previous_implementation_round_trips_byte_for_byte`), `ratchet::checkpoint` (`earlier_chains_round_trip_and_their_rules_are_enforced`) | runtime, local relay over TCP; unit |
| two OS processes | `a_peer_in_another_process_answers_over_the_relay` | runtime |
| a relay at an onion address (V2; V1 also in upper case and with one or two final dots): every connection goes only through the onion path, to exactly the address as given, and gets the 60 s request deadline; without Tor every operation fails with Tor's error and the direct path is never asked; a relay at an ordinary address goes only the direct way with 30 s, and never asks for Tor | `tests::relay_onion` | runtime, local V2 and V1 relays; Tor and TCP stand-ins that record each address |
| the process's Tor client: started once and shared; a failed start `Failed`, and within 60 s every call fails at once with its error, starting nothing; a caller that waits on a failing start does not start another; `tor_state()` answers `Starting` at once during a start; a start that panics leaves `Failed`; `NeedsUpdate` its own state and text, and within the pause every call fails at once with it; the process's client pauses 60 s; the Tor connector waits 60 s for a stream (longer if the connection's timeout is) and passes every call on to the stream (reads, writes, flushes, every read and write timeout); opening a core installs ring and names `tor/` next to the store; onion names told apart; the isolation group of each connector | `network::tor::tests`, `core-transport` `connector::tests::each_connector_has_an_isolation_group_of_its_own` | unit, stand-ins for the Tor client and its stream; no real Tor |
| what Settings says about the route: the core's onion rule written again in Kotlin, on the core's host cases and more (V2; V1 in any case, with final dots, brackets, more labels, a second ':'; non-ASCII look-alikes not onion); the direct label for an ordinary relay whatever Tor's state; through Tor with each state's own text, and alone before the first read | `RelayRulesTest.onlyARelayAtAnOnionAddressGoesThroughTor`, `RouteTextTest`; `TwoDeviceMessengerTest.switchesToTheEncryptedRelay` (the direct label on the screen) | JVM unit; emulator for the direct label only; no screen test with an onion relay |
| Android app ↔ host peer through a relay | `NetworkMessagingInstrumentationTest` on the emulator | Android runtime (emulator + host) |
| plaintext never reaches the relay | relay canary in every test | runtime |
| conversation history, states, repeats, replays, forged bundle, conflict | `tests::chat` | runtime |
| a conflict raised only by an authenticated first message (R-13 option A): a forged handshake and first message beside an own session raise nothing, in both key orders; a genuine simultaneous start is flagged only once its first message authenticates and resolves as before, in both key orders; an unanswerable handshake beside an own session is refused; the record beside goes on confirmation, removal and deletion; stores from earlier builds (the old conflict flag, a stale record beside an established session); process death after recording and after flagging; the dead end now reached only by a replay, and its way out | `tests::false_conflict`, `tests::delete_contact` | runtime, local relay over TCP; process crash |
| first contact to an offline recipient: 2, 3 and 5 contenders, both key orders, a conflict after a refusal; refusal limits; a refusal lost on the relay, sent again after the interval; forged, foreign, mismatched, swapped-role, replayed and late refusals; an elicited refusal the initiator can make alone and a third party cannot check; a refusal the relay refuses or whose connection breaks, sent later; process death at each restart step | `tests::first_contact` | runtime, local relay over TCP; process crash |
| refusal tag: both parties compute it, third parties cannot; bound to both keys, the roles and every field byte; low-order keys; byte-for-byte vector computed independently with Python `cryptography` | `core_crypto::refusal_mac` tests | unit; known answer |
| history pages (sizes 1, 7, 200, new entries while paging), the open-entry record against a full scan (random steps, a history from before the record, a conflict), process death after its writes | `tests::history_paging` | runtime; process crash |
| process death while sending from or receiving into the history | `tests::network_crash` (`chat_*` points) | process crash |
| cancelling a text: queued, pending and transmitted texts, a copy already on the relay that still arrives, a receipt taken before the cancel, refusals, a restart, sending again; process death between marking and abandoning | `tests::cancel_text`; `tests::network_crash` (`cancel_*` points) | runtime, local relay over TCP; process crash |
