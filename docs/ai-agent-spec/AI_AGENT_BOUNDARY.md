# AI Agent Boundary Specification

## 1. Status line

This is a boundary specification only. No agent exists in this codebase
today. No code is authorized by this document. Building any part of what
is described here requires a separate, explicit decision by the project
owner — this document defines limits an implementation would have to
satisfy, not a plan to build one.

---

## 2. Where the agent may live

**Recommended default: local-only (on-device, no network).**

Three options, in increasing order of risk:

- **Local-only** (on-device, no network calls): the assistant runs
  entirely on the user's device, with no path for private content to
  leave it. This is the only option that does not, by construction,
  create a new network exposure for an app whose entire value
  proposition is anonymity and E2E confidentiality (Tor onion routing +
  X3DH/Double Ratchet). Recommended as the **only default-safe option**.
- **Hybrid** (on-device + explicit remote calls with consent): remote
  calls may exist, but only for specific, user-initiated actions, never
  by default, and never carrying private message content unless the user
  has explicitly consented for that specific use. Higher risk than
  local-only because it requires a correctly-implemented consent gate to
  remain safe.
- **Remote** (private text leaves the device as a matter of course):
  highest risk. This option is incompatible with the app's stated threat
  model (anonymous, E2E-encrypted, Tor-routed) as a default behavior and
  is not recommended in any form.

Any remote processing of private content — under hybrid or otherwise —
requires per-use user consent and must be opt-in. It must never be the
default, and must never be implied by enabling the assistant generally.

---

## 3. What the agent MAY do (allow-list)

Starts minimal. Only capabilities that do not require reading
conversation content by default are listed. Each item states the data it
touches.

| Capability | Data touched |
|---|---|
| Explain security settings (e.g. what X3DH/Double Ratchet/Tor mean, what a setting controls) | None — static help content only |
| Search the user's OWN local messages, on explicit per-search request | Message plaintext, but only the specific scope the user requested for that one search, not a standing read |
| Draft a reply for the user to review and send manually | The conversation context needed to draft, with the draft never sent automatically — the user must review and send it themselves |
| Maintain a personal local note/journal for the user | Local notes content the user explicitly writes into the assistant; not conversation plaintext unless the user pastes it in themselves |

Nothing on this list grants standing or background access. Each row is a
single, user-initiated action with a bounded data scope.

---

## 4. What the agent MUST NOT do (hard prohibitions)

- Read conversations without explicit, per-scope user permission.
- Send any message autonomously.
- Access, derive, export, or log encryption keys.
- Weaken, bypass, or sit outside the E2E boundary.
- Transmit any private text to an external API without explicit consent.
- Run as a hidden or background agent.
- Access contacts, network, or PSI (private set intersection / contact
  discovery) data without explicit permission.

---

## 5. Data visibility table

| Data type | Default access | Access only with consent | Never |
|---|---|---|---|
| Message plaintext | No | Yes — per-use, scoped to the requested action (e.g. one search, one draft) | Standing/background read; export to external API without consent |
| Message metadata (timestamps, sender/recipient, delivery state) | No | Yes — only for a feature the user explicitly enabled for that purpose | Silent collection or transmission |
| Contacts | No | Yes — only for a feature the user explicitly enabled (e.g. assisted contact search) | Export off-device without consent |
| Encryption keys (X3DH/Double Ratchet/identity keys) | No | No — there is no consent level that permits this | Always — access, derivation, export, or logging in any form |
| Settings | Read access for explaining settings; no write access by default | Write access only if the user explicitly asks the assistant to change a setting | Silent modification of settings |
| Local notes/journal (assistant-specific) | Yes, for content the user explicitly wrote into this feature | — | Treating this store as a place to copy conversation plaintext into automatically |
| Network/Tor state | No | Yes — only to explain status (e.g. "is Tor connected") if the user asks | Modifying routing/connection behavior |

---

## 6. Consent model

- **Per-use consent**: required for any action that touches message
  plaintext, metadata, or contacts (e.g. "search my messages for X" —
  consent is implicit in the explicit request and scoped to that one
  action only).
- **Persistent consent**: may only be granted for a named, narrow feature
  (e.g. "always let the assistant search my local messages when I ask"),
  must be visible in settings as an explicit toggle, and must be
  revocable at any time with immediate effect.
- **Revocation**: revoking consent must immediately stop any further
  access of that type; it does not retroactively un-share data already
  processed, so per-use consent should be preferred over persistent
  consent wherever the capability allows it.
- **Default-deny rule**: any capability, data access, or behavior not
  explicitly permitted in Section 3 or the "access only with consent"
  column of Section 5 is forbidden. Silence in this document means "not
  allowed," not "undecided."

---

## 7. Threat notes

- **Plaintext exposure**: any code path that touches decrypted message
  content increases the attack surface for that content, even if it is
  never transmitted.
- **Key exfiltration**: an assistant with any access to key material
  could leak the means to decrypt all past and future traffic, not just
  one message.
- **Metadata leakage**: even without plaintext, who-talked-to-whom-when
  data can deanonymize users in a Tor-routed, anonymity-focused app.
- **Consent fatigue**: too many or poorly-scoped consent prompts train
  users to click through them, defeating the consent model in practice.
- **External-API leakage**: any remote call carrying private content
  creates a copy of that content outside the user's control and outside
  the app's E2E boundary.
- **Background exfiltration**: a hidden or always-on agent process is a
  standing channel for data to leave the device without a per-use user
  decision.

---

## 8. Open governance questions (owner decisions — not answered here)

These are decisions for the project owner to make. Provenance: owner →
decision. They are not inferable from this document and this document
does not answer them.

- Is hybrid (on-device + consented remote calls) ever allowed for this
  product, or is local-only a hard requirement, not just a recommended
  default?
- Does any feature justify reading message plaintext, even under
  per-use consent — or should plaintext access be excluded entirely
  regardless of consent?
- Local model only, or is remote processing permitted at all under
  consent, and if so, for which categories of data?
- Who is authorized to grant persistent consent on a shared or
  multi-profile device, if that scenario is ever supported?
- What happens to consent state on app reinstall, device transfer, or
  account recovery?
