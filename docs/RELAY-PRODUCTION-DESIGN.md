# Production relay — design proposal (for the Owner's decision)

Status: proposal only. Nothing here is implemented or decided. Each numbered
decision in section 6 needs the Owner's approval, because it changes the relay
protocol (`crates/relay/src/protocol.rs`, `RELAY_PROTOCOL_V1`) and adds a
cryptographic step (`CLAUDE.md`, "Обращение с криптокодом"). Written against
`main` @ `41a0d8d`.

## 1. What the relay is today

`crates/relay` is an untrusted store-and-forward relay (`server.rs`) and the
blocking client the app uses (`client.rs`), standard library only. Its own
documentation lists what it does not do (`server.rs:24-34`,
`bin/arcium-relay.rs:6-7`):

- **No authentication.** Anyone who reaches it can read or delete any
  mailbox and replace any bundle. This is tracker **R-9**: a reader of a
  mailbox learns whom its owner has pinned. It also feeds **R-14**: anyone can
  delete receipts.
- **No TLS.** A network observer sees every key, size and envelope.
- **No persistence.** A restart loses every mailbox, and with it any receipt
  the relay had accepted (R-14).
- **One thread per connection, no connection cap.**

Envelopes are end-to-end encrypted, and bundles are verified against the
pinned card. So none of the above exposes plaintext or keys. What it exposes
is metadata and availability.

## 2. Goals and non-goals

**Goals for this step**
1. Only a mailbox's owner can read it or delete from it, and only the owner
   can publish its bundle.
2. A network observer between the app and the relay sees neither keys nor
   envelopes, only that a connection to the relay exists, and its sizes and
   timing.
3. A relay restart loses nothing it has accepted.
4. Release builds can use a configured production relay. Today only debug
   builds accept a relay.

**Not in this step**
- Tor (F-15).
- Sealed sender: envelopes still name their sender in clear, so the relay
  still learns who writes to whom.
- Rate limiting beyond the mailbox cap and a per-address connection cap.
- Federation, or more than one relay.

## 3. Mailbox authentication (R-9)

A mailbox is addressed by its owner's X25519 identity key. Ownership must
therefore be proved with that key's secret.

An Ed25519 signature does not work. The contact card does not sign one key
with the other (`contacts.rs:17`, `CONTACT_CARD_V1`), so a relay that took a
signature would have to trust a first-come binding. An attacker could then
bind a victim's mailbox to the attacker's own signing key.

**Proposal: DH challenge-response with a relay authentication key.**

- The relay has a static X25519 key pair, its *auth key*, created once by
  `arcium-relay keygen`. The app pins the public half, together with the
  relay's address.
- After the channel is set up (section 4), the relay sends a fresh 32-byte
  challenge `c`.
- To act as owner `O`, the client sends
  `AUTH O tag`, where:
  - `k = HKDF-SHA256(ikm = DH(id_sk, auth_pk), info = "arcium-relay-auth-v1")`
  - `tag = HMAC-SHA256(k, c || exporter || O)`
- The relay checks the tag with `DH(auth_sk, O)`.
- `exporter` is 32 bytes of TLS keying material for this connection
  (RFC 5705 / 8446 exporter, label `"arcium-relay-auth-v1"`). A tag is
  therefore valid on one connection only.
- After a valid `AUTH`, the connection acts for `O`:
  - `FETCH`, `FETCH_AFTER` and `DELETE` are allowed only for recipient `O`;
  - `PUT_BUNDLE` only for owner `O`.
- `SEND` and `GET_BUNDLE` stay open to any connection. First contact needs
  both, and the sender's key is already in the envelope.

**Why this is sound, and what a review must confirm**

- Only the holder of `id_sk` can compute `k`, apart from the relay itself,
  which holds `auth_sk`.
- The relay learning `k` gives it nothing it could not compute itself. For
  any key it chooses, `DH(id_sk, pk)` is known to whoever holds that key's
  secret. This is the same position as an X3DH peer choosing an ephemeral key.
- The identity key is used in one more DH context, separated by the HKDF info
  string. That is cross-protocol key reuse, and it needs a cryptographic
  review: `arcium-security-review`, and an outside reviewer when available.
- A forged or replayed `AUTH` fails: the challenge is fresh and the exporter
  is bound to the connection.

Effect on findings:
- R-9: a stranger can no longer read a mailbox. The relay operator still can.
- R-14: only the relay operator can still delete receipts, and persistence
  removes restart loss.

## 4. Channel encryption

**Proposal: TLS 1.3 with rustls, the relay's certificate public key pinned in
the app.**

- rustls 0.23 is already in the app's dependency graph, through the vendored
  Tor client (`cargo tree -p mobile-ffi -i rustls`). The Android `.so`
  therefore gains little; the measured size change will be reported in the
  PR.
- **Pinning** (SHA-256 of the certificate's SubjectPublicKeyInfo) means no
  certificate authority and no domain name are needed: a self-signed
  certificate made by `arcium-relay keygen` is enough. A Let's Encrypt
  certificate can be added later without changing the app.
- The relay crate stops being standard-library only. The client stays
  blocking.
- If rustls's RFC 7250 raw-public-key mode works on both ends, X.509 can be
  dropped entirely. That is to be verified during implementation; the pin
  works either way.

**Alternatives considered**
- **Noise XK** (`snow` crate). One handshake would give both encryption and
  client authentication. But it is a new dependency, a second channel-crypto
  stack beside the TLS already linked, and it uses the identity key directly
  as a Noise static key, which is more key reuse than section 3. Not
  recommended.
- **Authentication without encryption.** It would close R-9 for strangers,
  but a network observer would keep seeing every mailbox key and envelope.
  Not recommended for production.

## 5. Persistence

**Proposal: SQLite, through `rusqlite`, which is already in the workspace
lockfile. It sits behind a cargo feature used only by the relay binary, so
the Android client does not change.**

- **Tables:** `envelopes(seq PRIMARY KEY, recipient, stored_at, bytes)`,
  `bundles(owner PRIMARY KEY, bytes)`, `meta(next_seq)`.
- **Durability:** `SEND` answers OK only after its row is committed (WAL,
  `synchronous=FULL`). Expiry by TTL runs as now; `DELETE` is a committed
  transaction.
- **Rules kept as today:** the mailbox cap, refusing to wrap sequence numbers,
  and deduplicating identical bytes still stored.
- **At rest:** envelopes are stored as received. They are already end-to-end
  encrypted; the metadata (keys, sizes, times) is not. Encrypting the disk
  is left to the host, and the deploy guide will say so.

## 6. Decisions for the Owner

1. Mailbox authentication: DH challenge-response with a pinned relay auth
   key (section 3). **Recommended.**
2. Channel: TLS 1.3 with rustls and a pinned key (section 4). **Recommended**,
   over Noise XK and over no encryption.
3. Persistence: SQLite, ciphertext stored as received, disk encryption left
   to the host (section 5). **Recommended.**
4. Compatibility: `RELAY_PROTOCOL_V2` only. The development relay and every
   test use V2 too, with keys generated at start-up, so one code path is
   tested. Older app builds cannot talk to a V2 relay. **Recommended**, since
   there are no users yet.
5. Order: three PRs, each with its own review and tests.
   1. TLS and authentication, in the relay and the client.
   2. Persistence.
   3. App configuration: release builds accept `host:port`, the TLS pin and
      the auth key, as one string or QR code from the operator.
   Then a deploy guide for the rented server.

## 7. What this does not establish

This is a design, not an implementation. Nothing is verified until the PRs
exist: no test, no review, and no measurement of size or latency. The
security argument in section 3 is the author's reasoning (INFERRED) and needs
the review named there.
