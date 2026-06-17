# Security Event Engine Specification

## 1. Status line

This is a specification only. No Security Event Engine exists yet. No AI
assistant exists yet. No implementation is authorized by this document.
Building anything described here requires a separate, explicit decision
by the project owner.

**Step 0 consistency check (performed before writing this document):**
`AI_AGENT_BOUNDARY.md` and `SECURITY_EVENT_CATALOG.md` were read in full.
No contradiction was found between those documents and this task: the
closed severity/send_policy/user_options vocabularies match, the
`continue_anyway` restriction on critical/encryption-failure events
matches, and the no-contact-identifier rule for `CONTACT_KEY_CHANGED` /
`CONTACT_NOT_VERIFIED` matches. This document proceeds on that basis.

---

## 2. Purpose

The Security Event Engine converts messenger system state into
deterministic security events and send policies, per the closed schema
defined in `SECURITY_EVENT_CATALOG.md`. The engine is useful even if no
AI assistant is ever built — it is the thing that makes the deterministic
UI in this app correct and trustworthy, independent of any future
assistant.

---

## 3. Pipeline

```
System State
  → Event Condition Check
  → Security Event
  → Send Policy
  → Deterministic UI
```

- **System State:** the messenger's current internal state (e.g. Tor
  connectivity, ratchet/session readiness, contact verification status).
- **Event Condition Check:** deterministic, code-defined conditions that
  decide whether a known event from the closed catalog applies right now.
- **Security Event:** one of the catalog's closed event objects (the five
  fields defined in `SECURITY_EVENT_CATALOG.md` Section 3 — `event`,
  `severity`, `send_policy`, `user_options`, `safe_message_key`).
- **Send Policy:** the `send_policy` value (`allow` / `warn` / `block`)
  carried on the event, enforced by the engine.
- **Deterministic UI:** a non-AI UI layer that renders the event using
  only its closed fields and the static string looked up via
  `safe_message_key`.

---

## 4. Engine authority

The engine owns:

- event emission
- severity
- send_policy
- the enforcement decision (e.g. actually blocking a send)

UI and AI may not override the engine. The UI may display the policy the
engine emitted. The UI may not bypass that policy. AI is out of scope for
this document and is not authorized by it.

---

## 5. Closed values

Matching `SECURITY_EVENT_CATALOG.md` exactly:

**Severity values are closed:** `info`, `low`, `medium`, `high`,
`critical`.

**send_policy values are closed:** `allow`, `warn`, `block`.

No additional severity or send_policy value is allowed without separate,
explicit review. This document does not add to either list.

---

## 6. Required examples

Each example shows condition → event → severity → send_policy →
deterministic UI behavior. All values match `SECURITY_EVENT_CATALOG.md`.

### `MESSAGE_ENCRYPTION_READY`

- **Condition:** encryption session is established and ready.
- **Event:** `MESSAGE_ENCRYPTION_READY`
- **Severity:** `info`
- **Send policy:** `allow`
- **Deterministic UI behavior:** sending may proceed; no warning shown.

### `TOR_DISCONNECTED`

- **Condition:** Tor route is unavailable.
- **Event:** `TOR_DISCONNECTED`
- **Severity:** `high`
- **Send policy:** `block`
- **Deterministic UI behavior:** sending is disabled; show reconnect
  guidance (`retry`, `cancel`).
- User options must not include `send_anyway` or `continue_anyway`.

### `MESSAGE_ENCRYPTION_FAILED`

- **Condition:** encryption session cannot be established, or message
  encryption fails.
- **Event:** `MESSAGE_ENCRYPTION_FAILED`
- **Severity:** `critical`
- **Send policy:** `block`
- **Deterministic UI behavior:** sending is disabled; show encryption
  failure warning (`retry`, `cancel`).
- User options must not include `send_anyway` or `continue_anyway`.

### `CONTACT_NOT_VERIFIED`

- **Condition:** contact verification is missing.
- **Event:** `CONTACT_NOT_VERIFIED`
- **Severity:** `medium`
- **Send policy:** `warn`
- **Deterministic UI behavior:** warn the user and offer a verification
  path (`verify_contact`, `continue_anyway`, `cancel`).

---

## 7. Alignment with Security Event Catalog

This specification respects the closed event schema from
`SECURITY_EVENT_CATALOG.md` in full:

- No event fields are added beyond the five closed fields (`event`,
  `severity`, `send_policy`, `user_options`, `safe_message_key`).
- No payload fields are added.
- No new event types are added beyond the catalog's initial nine.
- Contact identifiers are never serialized into events.

For contact events (`CONTACT_KEY_CHANGED`, `CONTACT_NOT_VERIFIED`):

- The deterministic UI may resolve local conversation context on its
  own (it already knows which conversation screen triggered the event).
- The event payload must not contain contact identifiers.
- The event payload must not contain phone numbers.
- The event payload must not contain usernames.
- The event payload must not contain PSI hashes.
- The event payload must not contain stable cross-session identifiers.

---

## 8. Continue-anyway restriction

This specification matches the catalog's `continue_anyway` restriction
exactly. For:

- `MESSAGE_ENCRYPTION_FAILED`
- any `critical` event
- any event whose `send_policy` is `block` because of an encryption
  failure

there must be no `send_anyway`, `continue_anyway`, `bypass`, `override`,
or `force_send` option, in the event's `user_options` or anywhere in the
deterministic UI. A `block` policy is enforced by the engine and cannot
be bypassed from the UI layer under any circumstance for these cases.

---

## 9. Logging and retention

Default: **no persistent event logs.** Security events can be
metadata-sensitive even without plaintext (e.g. a retained log of
`TOR_DISCONNECTED` or `CONTACT_KEY_CHANGED` events would itself be a
timeline of security-relevant activity). Any event retention is an owner
governance decision. If retention is ever allowed, it requires a
separate, explicit decision distinct from this document. This document
does not authorize event retention of any kind, for any duration.

---

## 10. AI out of scope

- The engine must work without AI.
- Deterministic UI is required.
- AI is out of scope for this document.
- No AI assistant is authorized by this document.
- No LLM calls are authorized by this document.

---

## 11. Open governance questions (owner decisions — not answered here)

Provenance: owner → decision. Not inferable from this specification.

- Should bare contact events ever reach a future AI explanation layer?
- Should critical events always bypass AI and use deterministic UI only?
- Should any event retention be allowed?
- What retention period, if any, is acceptable?
- What exact consent model applies if AI is ever added later?
- What exact definition of local-only applies if AI is ever added later?

---

## 12. Success criteria

A future engineer reading this document should understand:

- how to implement a deterministic Security Event Engine without AI;
- how system state becomes an event;
- how an event produces a send_policy;
- how deterministic UI displays the result;
- why the engine remains useful even if no AI assistant is ever built.

Nothing in this document authorizes implementation of the Security Event
Engine or any AI assistant.
