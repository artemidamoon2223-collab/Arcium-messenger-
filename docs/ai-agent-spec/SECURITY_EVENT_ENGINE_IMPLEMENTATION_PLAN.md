# Security Event Engine — Implementation Plan

## 1. Status line

This is a planning document only. No Security Event Engine exists yet.
No code is authorized by this document. Building anything described here
requires a separate, explicit decision by the project owner. AI is out of
scope and not authorized by this document.

---

## 2. Scope of v1

v1 implements exactly four events and nothing else:

- `MESSAGE_ENCRYPTION_READY` — severity `info`, send_policy `allow`
- `TOR_DISCONNECTED` — severity `high`, send_policy `block`
- `MESSAGE_ENCRYPTION_FAILED` — severity `critical`, send_policy `block`
- `CONTACT_NOT_VERIFIED` — severity `medium`, send_policy `warn`

**Why this set:** it exercises all three send_policy outcomes
(`allow`, `warn`, `block`) and both critical invariants the engine must
get right from the start:

- the `continue_anyway`-forbidden rule, via the critical,
  encryption-failure block (`MESSAGE_ENCRYPTION_FAILED`);
- the no-identifier-in-payload rule, via the contact event
  (`CONTACT_NOT_VERIFIED`).

All other catalogued events (`ROUTE_UNKNOWN`, `DIRECT_CONNECTION_BLOCKED`,
`CONTACT_KEY_CHANGED`, `SCREENSHOT_PROTECTION_OFF`,
`BACKUP_EXPORT_STARTED`) are explicitly deferred to later, separate
steps. v1 does not implement them.

---

## 3. Module boundary

The engine is a pure, deterministic unit:

- **Input:** a read-only system-state snapshot.
- **Output:** an event + send_policy (conforming to the closed schema).

The engine does **not** detect system state itself. It does not reach
into Tor, crypto, or PSI subsystems directly — it consumes a state
snapshot that something else provides to it. This boundary is described
here as an interface contract only; how the messenger produces that
snapshot is messenger internals and is out of scope for this plan.

---

## 4. Data types (described, not coded)

- **`SystemStateSnapshot`** — the minimal read-only inputs the engine
  needs, described abstractly: a Tor connectivity status, an encryption
  session readiness status, and a contact verification status. This plan
  does not specify how the messenger produces or represents these
  internally — only that the engine consumes them as already-known facts.
- **`SecurityEvent`** — matches the closed catalog schema exactly: five
  fields only — `event`, `severity`, `send_policy`, `user_options`,
  `safe_message_key`. No added fields. No contact identifiers, ever.
- **Severity set (closed):** `info`, `low`, `medium`, `high`, `critical`.
- **send_policy set (closed):** `allow`, `warn`, `block`.

---

## 5. Deterministic evaluation flow

```
SystemStateSnapshot -> condition checks -> SecurityEvent -> send_policy
```

The same snapshot must always yield the same event and the same policy.
No randomness, no time-dependence, no external calls inside this
evaluation step.

---

## 6. Event emission rules

### `MESSAGE_ENCRYPTION_READY`

- **Condition:** encryption session is established and ready.
- **Event:** `MESSAGE_ENCRYPTION_READY`
- **Severity:** `info`
- **send_policy:** `allow`
- **user_options:** none (empty)
- **Deterministic UI behavior:** sending may proceed; no warning shown.

### `TOR_DISCONNECTED`

- **Condition:** Tor route is unavailable.
- **Event:** `TOR_DISCONNECTED`
- **Severity:** `high`
- **send_policy:** `block`
- **user_options:** `retry`, `cancel`
- **Deterministic UI behavior:** sending is disabled; show reconnect
  guidance.
- `user_options` contains no `send_anyway`, `continue_anyway`, `bypass`,
  `override`, or `force_send`.

### `MESSAGE_ENCRYPTION_FAILED`

- **Condition:** encryption session cannot be established, or message
  encryption fails.
- **Event:** `MESSAGE_ENCRYPTION_FAILED`
- **Severity:** `critical`
- **send_policy:** `block`
- **user_options:** `retry`, `cancel`
- **Deterministic UI behavior:** sending is disabled; show encryption
  failure warning.
- `user_options` contains no `send_anyway`, `continue_anyway`, `bypass`,
  `override`, or `force_send`.

### `CONTACT_NOT_VERIFIED`

- **Condition:** contact verification is missing.
- **Event:** `CONTACT_NOT_VERIFIED`
- **Severity:** `medium`
- **send_policy:** `warn`
- **user_options:** `verify_contact`, `continue_anyway`, `cancel`
- **Deterministic UI behavior:** warn the user and offer a verification
  path.

---

## 7. send_policy enforcement

send_policy is owned by the engine. The UI may display the policy the
engine emitted. The UI may not bypass it. A `block` policy is enforced by
the engine; no UI path can send while a `block` policy is in effect for
the current attempt.

---

## 8. Deterministic UI integration points

Named as an interface contract only — messenger UI internals are out of
scope for this plan:

- The UI receives `(event, send_policy, user_options)` from the engine.
- The UI renders these deterministically, using the static string looked
  up via `safe_message_key`.
- The UI never originates a security fact and never overrides a
  send_policy it received.

---

## 9. Contact-event payload rule

For `CONTACT_NOT_VERIFIED`: the event payload contains no contact
identifier, phone number, username, PSI hash, or stable cross-session
identifier. Any local conversation context needed to show "which
contact" is resolved entirely inside the deterministic UI, using context
the UI already has — it is never serialized into the event. This matches
the resolution already recorded in `SECURITY_EVENT_CATALOG.md`.

---

## 10. Test strategy (tests precede implementation)

Required tests, described and not coded:

- **Determinism:** an identical snapshot fed to the engine repeatedly
  always yields an identical event and policy.
- **One test per v1 event:** each of the four v1 events is verified to
  produce the correct event name, severity, and send_policy for its
  triggering condition.
- **Enforcement invariant:** for both `block` events
  (`TOR_DISCONNECTED`, `MESSAGE_ENCRYPTION_FAILED`), the emitted
  `user_options` exposes no send/continue/bypass-class option.
- **Payload invariant:** the `CONTACT_NOT_VERIFIED` event carries no
  identifier-class field of any kind.
- **Closed-value invariant:** no emitted event uses a severity or
  send_policy value outside the closed sets in Section 4.

All tests operate on the engine as a pure unit, with no messenger
internals (no real Tor, crypto, or PSI subsystem involved).

---

## 11. Non-goals (explicit exclusions)

- No code authorization.
- No AI.
- No LLM calls.
- No autonomous behavior.
- No network calls.
- No persistent event logs.
- No analytics.
- No plaintext access.
- No contact-identifier serialization.
- No crypto-protocol changes.
- No Tor-routing changes.
- No new event types beyond the four v1 events.
- No future-AI integration hook of any kind.

---

## 12. Logging / retention

Default: no persistent event logs. Retention is a separate owner
decision; this document neither specifies nor authorizes it.

---

## 13. Rollout order

```
Plan -> tests defined -> (separate explicit decision) -> implementation
of the four v1 events -> later, separate steps for additional catalog
events
```

Crossing from this plan to actual code requires a distinct authorization
that is not granted by this document.

---

## 14. Open governance questions (owner decisions — not answered here)

Provenance: owner → decision. Not inferable from this plan.

- Should additional catalog events follow v1, and in what order?
- Should any event retention ever be allowed, and for how long?
- Should a future AI explanation layer ever exist, and under what
  consent model?
