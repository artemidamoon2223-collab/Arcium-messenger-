---
name: mbr-integration
description: "What the MBR durable-history research established, what it only assumes, and how its mechanisms map onto Arcium's existing Rust/Kotlin session lifecycle. Use when a task touches durable session state, crash recovery, message persistence, outbox/retry, ACK semantics, rollback or replay protection, skipped-key retention, or when MBR, CommitAnchor, an external witness, or findings C-01/C-02/C-03 are mentioned. Describes evidence and architecture only — it authorizes no implementation, no cryptographic change, and no witness integration."
---

# mbr-integration

## Status

Knowledge and judgment aid. Everything here is either a **verified fact** with a
citation, an **experimental finding** with its provenance, or a **proposal that
is not implemented**. The three are labelled separately throughout and must not
be collapsed. Arcium-side facts were verified at commit `99c9f49`; re-derive
before relying on any of them — `references/arcium-integration-map.md` carries
the commands.

## This skill authorizes nothing

Reading or invoking it is not an instruction to build anything. Each of the
following needs its own explicit owner authorization, named in the task:

- modifying cryptographic primitives or a frozen protocol format;
- replacing or rewriting Arcium's Double Ratchet or X3DH;
- integrating an external witness / commit authority;
- changing the session trust model;
- changing persistent storage formats;
- committing, pushing, opening or merging a PR.

`repo-change-protocol` governs *how* authorized work is carried out;
`engineering-code-review` governs scope discipline and how claims are worded.
This skill adds only the MBR-specific subject matter.

## Use when

- a task touches durable session state, crash recovery, or process-death survival;
- outbox, retry, message identity, ACK, duplicate delivery, or replay come up;
- skipped-key retention, bounded structures, or state growth come up;
- rollback, history continuity, CommitAnchor, or an external witness come up;
- someone cites MBR, C-01, C-02, C-03, or "27/27".

## Do not use when

- the work is ordinary X3DH / Double Ratchet / PSI / transport work with no
  durable-state angle — those belong to the crypto rules in `CLAUDE.md`;
- the question is how UniFFI bindings are generated or packaged — that is
  `android-uniffi-bridge`;
- the question is repository layout — that is
  `engineering-code-review/references/repo-map.md`.

## The five categories — keep them apart

Every statement about MBR belongs to exactly one. Say which one you are in.

1. **Established Arcium implementation fact** — traced to file and line in this
   repository, re-derivable today.
2. **MBR experimental finding** — observed by running the reference package.
   Carries provenance: which artifact, which hash, which test.
3. **Proposed integration architecture** — design only. Never describe it in the
   present tense; Arcium does not have it.
4. **Unresolved security assumption** — stated, not settled. Includes everything
   the external-authority model rests on.
5. **Owner-authorized engineering task** — what was actually asked for, this time.

Confusing 2 with 3 is the failure mode this skill exists to prevent: a mechanism
demonstrated in a 340-line Python prototype is not a feature of Arcium.

## What MBR is

Cryptographic History Integrity: wrap a conventional ratchet in a transactional
commit boundary, so that the next cryptographic state, the outgoing artifact,
the received event and the application's acceptance of it become durable in one
atomic step — and so no artifact is released before that step commits. It is a
**state-machine discipline around** cryptography, not new cryptography. Not
proven, not audited; no comparison to Signal is supported.

## The split that governs every decision

**Local mechanisms** — guarded durable transition, immutable outbox, exact event
identity, ACK bound to an exact artifact, atomic receive acceptance, bounded
retention, recovery handles, explicit states. No network, no third party, full
value on their own.

**Strict rollback resistance** — requires state that cannot be rolled back with
the endpoint database. Needs an external authority, protected hardware, or a
peer. Carries availability, centralization and **metadata** costs that collide
with Arcium's anonymity goal.

Never present these as one package. Local work can proceed on its own merits;
rollback resistance is a separate product decision that is not yet made.

## Two rules that come from Arcium's own history

**One authority over the session.** Rust owns every durable state transition;
Kotlin receives opaque handles, public event ids and status — never secrets, and
never a callback inside the commit boundary. Not theoretical: `MessageRepository.kt`
documents removing a Kotlin mirror of session state that could record an owner
before the FFI call creating the session had succeeded.

**One `put` is not a transaction for two writes.** A mutex serializes threads; it
does not make two SQLite writes one commit.

## Finding the smallest safe change

1. Name the category the task falls in.
2. Name the invariant at stake and whether Arcium holds it today — by file and
   line, not from memory.
3. Ask what breaks if the process dies at each boundary the change introduces.
4. Prefer the option with no new trust assumption and no new failure domain.
5. If it needs an authority, hardware or the network, it is research — say so.

## Evidence discipline

Green tests prove the run finished. A repair is only meaningful when its
counterexample still reproduces against the **unfixed baseline**. Preserve
failing traces; never retune an expectation after seeing a result unless the
test was objectively mis-specified — and record that it was.

## References

- `references/evidence-ledger.md` — what MBR demonstrated, with artifact hashes,
  minimal counterexample traces, and the declared negative results.
- `references/arcium-integration-map.md` — verified Arcium state per mechanism,
  re-derivation commands, and the proposed (not implemented) staging.
