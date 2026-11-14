# Session recovery — options (design note, no decision)

**Status:** proposal only, written 2026-11-14 against `main` @ `de328a1`.
Nothing here is implemented or decided.

Each option changes durable-state rules, the protocol, or both. So each one
needs:
- an explicit Owner decision;
- its own task and PR;
- `arcium-security-review` before acceptance (`CLAUDE.md`, «Обращение с
  криптокодом»).

This note does not change the wire format, the stored format or any
cryptographic parameter.

## 1. The problem

Two rules hold today:
- a peer has at most one session;
- an established session is never replaced or removed.

| rule | where |
|---|---|
| a session that has committed a message from the peer cannot be removed | `docs/S2-B2-DURABLE-MESSAGING.md` section 6a, `SessionEstablished`; `crates/core-protocol/src/messaging/removal.rs:75-77` |
| a handshake for a peer that has a session is dropped | `crates/mobile-ffi/src/network.rs:921-934` |

The spec already names the missing piece: resetting a session "needs a
peer-authenticated protocol, which does not exist here" (S2-B2 section 6a).
Without one, three situations have no way out.

| # | situation | evidence |
|---|---|---|
| 1 | **False conflict** (tracker R-13). An unauthenticated handshake "from" the contact raises a conflict. Resolving it removes this device's session while the contact goes on to accept it. One side waits for a handshake that never comes; the other holds an established session. | RUNTIME_VERIFIED by a probe at `de328a1` (not committed; see R-13) |
| 2 | **More than `MAX_SKIP` (1000) messages lost in one sending chain** (tracker R-14). Every later message of that chain fails `SkipLimit`, so that direction stops for good. | RUNTIME_VERIFIED by a probe at `de328a1` (not committed; see R-14); `crates/core-crypto/src/ratchet.rs:41`, `:296-299` |
| 3 | **A damaged session or handle record.** It is "never replaced by a new session" (S2-B2 section 4) and its removal is refused (`InvalidSession` / `MissingSession`, section 6a). | SOURCE_VERIFIED in the spec; no probe |

A lost master key (F-9) is an identity-level loss, not a session-level one,
and is out of scope here.

## 2. What any option must keep

- **No silent replacement by a third party.** Whoever can write to the relay
  (today anyone: no relay authentication, R-9) must at most delay a session.
  They must never be able to replace it, read it or make it forget messages
  already delivered.
- **Pinned identities.** A new session with a contact is keyed from that
  contact's pinned card, exactly as today (`docs/NET-MESSAGING.md` section 2).
- **No replay.** A recorded handshake and first message must not be able to
  replace a session again. Today replay is stopped by the one-time prekey
  being consumed. The prekey-less path (X-6) must be closed before any option
  lets a handshake replace an existing session.
- **Durability.** Every step is one S2-B2 transaction, and a crash between
  steps is safe to repeat.
- **Honest delivery state.**
  - A text committed under the old session must not become `Delivered` unless
    the old session's receipt arrives.
  - A text that is given up is shown `NotDelivered`, and the user sends it
    again. Nothing is resent automatically (NET-MESSAGING section 8).

## 3. Options

### C. Delete a contact completely (local only; no wire change)

**What it is**
- A user action "delete contact" removes, in one transaction:
  - the pinned card;
  - the session (established or not) and its handle;
  - the provisional handshake;
  - the outbox entries and the chat history for that contact.
- The `seen:` and `sendid:` records stay, as they already do on removal
  (S2-B2 section 6a), so nothing is encrypted twice for one logical id.
- To recover, **both** users delete each other and exchange cards again.
  Neither device then holds a session, and the next text starts a fresh one.

**What it solves:** situations 1, 2 and 3, once both users do it.

**What it costs:**
- It needs coordination out of band, for example a phone call.
- Everything not yet delivered, on either side, is lost.
- It changes the S2-B2 section 6a rule from "an established session is never
  removed" to "never removed except by an explicit delete of the contact".

**Risk:** low. Only the device's own user can trigger it, and it uses no new
protocol message.

### A. Stop false conflicts at the source (local only; no wire change)

**What it is**
- A handshake that arrives while this device holds its own unconfirmed
  session does not raise a conflict by itself. It is recorded provisionally,
  as a responder records one today.
- A conflict is raised only when the contact's first message (OPEN) under
  that handshake authenticates, which needs the contact's identity secret.
- Until then, the handshake replaces nothing and changes no flag.

**What it solves:** situation 1. A forged or replayed handshake can no longer
start the dead end. A genuine simultaneous start is still detected and
resolved as today.

**What it costs:**
- A new durable record: a provisional handshake held next to the device's own
  initiator session, which S2-B2 section 4 does not allow today.
- An S2-B2 spec change, plus a migration rule for stores written before it.

**Risk:** medium. It touches first-contact state, which R-1 and R-12 changed
recently.

### B. Peer-authenticated session replacement (protocol change)

**What it is**
- A new handshake from a pinned contact is recorded provisionally even when a
  session exists.
- When that handshake's first message authenticates, the old session is
  retired in the same transaction and the new one takes its place:
  - pending texts of the old session become `NotDelivered`;
  - the user is told "the contact restarted the session".
- Either user can start the replacement ("reset session"). A device may also
  start one itself after a bounded period without progress, for example while
  waiting in `AwaitingPeerSession`.

**What it solves:** situations 1, 2 and 3 without out-of-band coordination,
on both sides.

**What it costs:**
- It needs a stated rule for which handshake wins when both sides reset at
  once (the same greater-key rule as `resolve_session_conflict` is one
  choice).
- X-6 must be closed first, and replays of an older handshake must be refused
  (one-time prekey consumed; signed prekey unchanged).
- Wire bytes need not change. The acceptance rule does change, which is a
  protocol change under `CLAUDE.md`.

**Risk:** highest of the three. Anyone holding the contact's identity secret
can force resets, but that secret already lets them impersonate the contact.
It needs a cryptographic review, together with the refusal MAC of R-1
(REVISIT AT SECURITY AUDIT).

## 4. Smaller related items (independent of the above)

- **R-15: a text that is never acknowledged stays `Transmitted` for good.**
  A user-facing "cancel" could call the existing internal `abandon_outgoing`
  (`crates/mobile-ffi/src/messaging_api.rs:320`).
  - The text would then be shown as "cancelled, may still arrive", not
    `NotDelivered`: it may already be on the relay.
  - It needs a new entry state and an export decision. `abandon_outgoing` is
    deliberately not exported (NET-MESSAGING section 5), so any export must
    keep the X-4 guarantees.
- **R-14 could be made less likely without a reset.** Raising `MAX_SKIP` only
  moves the threshold, and costs stored skipped keys
  (`MAX_SKIPPED_KEYS`, `crates/core-crypto/src/ratchet/checkpoint.rs`). It is
  not recommended on its own.

## 5. Suggested order

1. **C**, the escape hatch. Smallest, local, and only the user can trigger it.
2. **A**. It removes the most reachable trigger of situation 1.
3. **B**, only if automatic recovery is wanted. It comes after the relay gets
   authentication (R-9) and after X-6 is closed.

Each step: Owner decision, then its own PR with tests that reproduce the
situation first and fail on the base. Then `engineering-code-review` and
`arcium-security-review`, and a tracker PR after the merge.
