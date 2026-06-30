# Security Event Catalog

## 1. Status line

This is a catalog/specification only. No Security Event Engine exists
yet. No AI assistant exists yet. No implementation is authorized by this
document. Building anything described here requires a separate, explicit
decision by the project owner. This document narrows what a future
implementation would be allowed to do — it does not start one.

This document assumes, but does not re-authorize, the boundary already
defined in `docs/ai-agent-spec/AI_AGENT_BOUNDARY.md`: any AI assistant
remains optional, local-only by default, and consent-gated for anything
beyond static explanation.

---

## 2. Architecture boundary

**Core principle: the Security Event Engine creates security facts. AI
does not create security facts. AI only explains already-emitted
events.**

### Security Event Engine

- Deterministic messenger code (no AI involvement in this component).
- Emits structured security events from the closed schema in Section 3.
- Owns severity assignment.
- Owns send policy (allow / warn / block).
- Owns enforcement — blocking a send, requiring verification, etc.
- Remains authoritative at all times. Nothing downstream can change a
  fact this engine has already emitted.

### AI Assistant (optional, future, not authorized here)

- An optional future consumer of events emitted by the engine.
- Receives only safe structured events conforming to Section 3.
- May explain an event to the user in natural language.
- Cannot override send policy.
- Cannot originate security facts.
- Cannot change severity.
- Cannot create new event types.

The engine decides. The assistant, if it ever exists, explains.

---

## 3. Event schema

A minimal event object:

```
{
  "event": "TOR_DISCONNECTED",
  "severity": "high",
  "send_policy": "block",
  "user_options": ["retry", "cancel"],
  "safe_message_key": "tor_disconnected"
}
```

Allowed fields are **closed and exhaustive**. Only these five fields may
ever exist on a security event:

- `event`
- `severity`
- `send_policy`
- `user_options`
- `safe_message_key`

Any additional field makes the event invalid. There is no general-purpose
payload, metadata, or extension field. In particular, an event must never
carry: free-form plaintext, contact identifiers, message content,
usernames, phone numbers, PSI hashes, cryptographic keys, IP addresses,
Tor circuit details, routing details, or message metadata beyond the
five fields above.

### `safe_message_key`

- Must be one value from a closed, predefined catalog of UI string keys.
- It is a lookup key into static UI strings, nothing else.
- It is never free-form text.
- It is never user-generated.
- It is never interpolated with runtime data.
- It must never contain message content, contact names, usernames, phone
  numbers, identifiers, PSI-derived values, or any other runtime-generated
  text.

### Schema consistency note (contact-related events)

Section 5's special rule for `CONTACT_KEY_CHANGED` and
`CONTACT_NOT_VERIFIED` refers to an "opaque local contact handle." To stay
consistent with the closed five-field schema above, that handle is **not**
a field on the security event object and is never passed to an AI
explanation layer. Any association between an event and a specific
contact or conversation is resolved entirely inside the deterministic
messenger UI, using context the UI already has (e.g. which conversation
screen emitted the event) — never by adding a sixth field to the event
schema. The event object itself stays contact-agnostic.

---

## 4. Allowed values

**Severity:** `info`, `low`, `medium`, `high`, `critical`

**Send policy:** `allow`, `warn`, `block`

**User options:** `retry`, `cancel`, `continue_anyway`, `open_settings`,
`verify_contact`

**Rule:** `continue_anyway` must **not** appear:

- on any `critical` event;
- on `MESSAGE_ENCRYPTION_FAILED`;
- on any event whose `send_policy` is `block` because of an encryption
  failure.

This restriction is enforced explicitly in each catalog entry below, not
left implicit.

---

## 5. Initial allowed event catalog

### 1. `TOR_DISCONNECTED`

- **Trigger:** The app loses its Tor connection while connectivity is
  expected (e.g. mid-session or before a send).
- **Severity:** `high`
- **Send policy:** `block`
- **User options:** `retry`, `cancel`
- **Allowed payload fields:** the five schema fields only.
- **Forbidden payload fields:** IP addresses, relay/node identifiers,
  circuit IDs, routing path details.
- **Example user-facing explanation:** "Your connection through Tor was
  lost, so this message wasn't sent. You can retry or cancel."

### 2. `ROUTE_UNKNOWN`

- **Trigger:** The app cannot confirm the current Tor route status before
  a send.
- **Severity:** `medium`
- **Send policy:** `warn`
- **User options:** `retry`, `cancel`
- **Allowed payload fields:** the five schema fields only.
- **Forbidden payload fields:** circuit details, relay identifiers, IP
  addresses, routing path.
- **Example user-facing explanation:** "We can't confirm your message's
  route right now. You can retry or cancel."

### 3. `DIRECT_CONNECTION_BLOCKED`

- **Trigger:** The app detects and blocks a non-Tor direct connection
  attempt.
- **Severity:** `high`
- **Send policy:** `block`
- **User options:** `retry`, `cancel`
- **Allowed payload fields:** the five schema fields only.
- **Forbidden payload fields:** IP addresses, destination host/port,
  routing information.
- **Example user-facing explanation:** "A direct, non-Tor connection
  attempt was blocked to protect your anonymity. You can retry through
  Tor or cancel."

### 4. `MESSAGE_ENCRYPTION_READY`

- **Trigger:** An end-to-end session/ratchet is established and ready
  before a send.
- **Severity:** `info`
- **Send policy:** `allow`
- **User options:** none (empty list)
- **Allowed payload fields:** the five schema fields only.
- **Forbidden payload fields:** key material, ratchet state, contact
  identifiers.
- **Example user-facing explanation:** "Your message is end-to-end
  encrypted and ready to send."

### 5. `MESSAGE_ENCRYPTION_FAILED`

- **Trigger:** An encryption operation fails before a send.
- **Severity:** `critical`
- **Send policy:** `block`
- **User options:** `retry`, `cancel` — **`continue_anyway` is forbidden
  on this event** (per Section 4 rule; this is a critical, encryption-
  failure block).
- **Allowed payload fields:** the five schema fields only.
- **Forbidden payload fields:** error internals, key material, message
  content, stack/crypto diagnostic detail.
- **Example user-facing explanation:** "Your message could not be
  encrypted, so it was not sent. You can retry or cancel."

### 6. `CONTACT_KEY_CHANGED`

- **Trigger:** A contact's identity key has changed since it was last
  seen/verified.
- **Severity:** `high`
- **Send policy:** `warn`
- **User options:** `verify_contact`, `continue_anyway`, `cancel` —
  `continue_anyway` is permitted here because this event is `high`, not
  `critical`, and its `block`/`warn` status is not an encryption-failure
  block.
- **Allowed payload fields:** the five schema fields only. See "Special
  rule for contact events" below for how contact association is handled
  outside the schema.
- **Forbidden payload fields:** phone number, username, contact name, PSI
  hash, account identifier, global identifier, any stable cross-session
  identifier, any value usable for cross-user correlation.
- **Example user-facing explanation:** "This contact's security key has
  changed. You can verify them, continue anyway, or cancel."

### 7. `CONTACT_NOT_VERIFIED`

- **Trigger:** Sending to, or receiving from, a contact whose key has
  never been verified out-of-band.
- **Severity:** `medium`
- **Send policy:** `warn`
- **User options:** `verify_contact`, `continue_anyway`, `cancel`
- **Allowed payload fields:** the five schema fields only. See "Special
  rule for contact events" below.
- **Forbidden payload fields:** same list as `CONTACT_KEY_CHANGED`.
- **Example user-facing explanation:** "This contact's identity hasn't
  been verified yet. You can verify them, continue anyway, or cancel."

**Special rule for contact events** (`CONTACT_KEY_CHANGED`,
`CONTACT_NOT_VERIFIED`): the event may indicate that a contact-related
security state changed; it may never identify the contact. Any opaque
local contact handle needed to show "which contact" in the deterministic
UI is resolved locally by the messenger UI from its own existing state
(see Section 3's schema consistency note) — it is never encoded into the
event object, and is never available to an AI explanation layer.

### 8. `SCREENSHOT_PROTECTION_OFF`

- **Trigger:** Screenshot protection is disabled while viewing a chat.
- **Severity:** `low`
- **Send policy:** `allow`
- **User options:** `open_settings`
- **Allowed payload fields:** the five schema fields only.
- **Forbidden payload fields:** chat/contact identifiers, message
  content.
- **Example user-facing explanation:** "Screenshot protection is off for
  this chat. You can open settings to turn it on."

### 9. `BACKUP_EXPORT_STARTED`

- **Trigger:** A user-initiated local backup export begins.
- **Severity:** `medium`
- **Send policy:** `allow`
- **User options:** `cancel`
- **Allowed payload fields:** the five schema fields only.
- **Forbidden payload fields:** file paths, backup contents, key
  material.
- **Example user-facing explanation:** "A backup export has started. You
  can cancel it if this wasn't intentional."

---

## 6. Hard-forbidden event categories

Events are forbidden if they contain, or are derived from:

- message plaintext
- message previews
- message topics
- message sentiment
- password detection
- link detection
- file contents
- contact phone numbers
- usernames
- PSI hashes
- cryptographic keys
- Tor circuit details
- IP addresses
- routing information
- behavioral profiling
- communication graph analysis

**Content-derived events are forbidden. Metadata-rich events are
forbidden. Security events describe the security envelope. Security
events do not describe conversation contents.**

---

## 7. AI assistant restrictions

The optional AI assistant must never:

- originate security facts
- inspect message content
- inspect contacts
- inspect keys
- inspect PSI data
- inspect Tor circuit details
- inspect IP addresses
- change severity
- change send_policy
- unblock blocked sends
- auto-send messages
- auto-retry actions
- execute actions automatically
- run hidden/background analysis

The assistant explains. The engine decides.

---

## 8. Deterministic UI fallback

Every event must be understandable through deterministic UI alone, using
only `severity`, `send_policy`, `user_options`, and the static string
looked up via `safe_message_key`. The Security Event Engine must provide
full value even if no AI assistant is ever built. AI is optional;
deterministic UI is required. If AI is removed entirely, the event system
remains fully functional with no loss of security-relevant behavior.

---

## 9. Open governance questions (owner decisions — not answered here)

Provenance: owner → decision. Not inferable from this document.

- Should contact-key events (`CONTACT_KEY_CHANGED`, `CONTACT_NOT_VERIFIED`)
  ever pass through an AI explanation layer at all?
- Should contact-key events remain deterministic-UI-only, permanently?
- Should `critical` events bypass AI entirely, even for explanation?
- Is remote AI ever allowed for low-sensitivity security events?
- What consent is required before AI explains any event, even a
  low-severity one?
- Are precise timestamps ever allowed on an event, or only ordering?
- What is the exact technical definition of "local-only" for this
  product (e.g. does it permit on-device models distributed via network
  update, or none at all)?

---

## Closing note

This catalog is closed: an unlisted event type is forbidden, and adding a
new event requires a separate review, not an extension of this document
in place. Nothing in this document authorizes implementation of the
Security Event Engine or any AI assistant.
