# MBR evidence ledger

What the research actually demonstrated, and what it did not. Every row is
category 2 (experimental finding) or category 4 (unresolved assumption) — see
`SKILL.md`. Nothing here is a fact about Arcium.

## Artifacts and provenance

| artifact | SHA-256 | how verified |
|---|---|---|
| `mbr_next_v0_1.py` (canonical v0.1) | `ebc710f1cabc1bd31cc61696cc391a4e92a4244ea4d2a477c9a95157443ec655` | verified twice independently; the v0.3 package embeds the same file at the same hash |
| `test_mbr_next_v0_1.py` | `a07b5892df414a42e65372cac2c2ef43fb280bb1f94af3877547d2ce556f2893` | as above |
| `MBR-PRE-ARCIUM-v0.3_FULL_PACKAGE.zip` | `f85aa6acbea2222d4ced8fe6c0532141c0503dba039a4bcbbb4ccdb261854e1b` | 20 files, internal `SHA256SUMS.txt` 19/19 OK |

The published hash caught a real transfer error during review (one character
corrupted while the file size stayed identical). Always verify before reasoning
about contents.

## Counterexamples against v0.1 — reproduced, minimal, deterministic

**C-01 — keystream reuse under sender rollback.** 3 events:
`SNAPSHOT(A) ; SEND("AAAA") ; ROLLBACK_DB(A) ; SEND("BBBB")`. Two published
ciphertexts with identical `(dh, n, g)` under a constant zero nonce; proved by
XOR, not by argument: `c1 ⊕ c2 = p1 ⊕ p2`. Deterministic 5/5. An honest receiver
rejects the second artifact, which does **not** undo the disclosure.

*The distinction that matters:* a crash before commit also rewinds the
generation and is **safe** — the crashed attempt released no ciphertext, so the
key was used once in the world. Rollback is unsafe because it rewinds past a
committed send whose bytes were already returned. Any Arcium design must
preserve that asymmetry.

*Scope:* C-01's keystream reuse depends on the constant zero nonce of the v0.1
reference. Do not attach the C-01 label to any other state/publication ordering
defect — see risk 5 in `arcium-integration-map.md`.

**C-02 — double application under receiver rollback.** 4 events:
`SNAPSHOT(B) ; SEND ; RECEIVE ; ROLLBACK_DB(B) ; RECEIVE`. Both deliveries
report `duplicate=False`; plaintext emitted twice; identical ACK re-emitted.
Deterministic 5/5. Deduplication lived entirely in rows the rollback reverted.

**C-03 — unbounded persistent structures.** `retired` grows **67 bytes per
turn**, linear, no plateau, with no eviction path anywhere. Independently
measured twice (review campaign and the v0.3 package agree on 67). `inbox`,
`outbox` and `history` also grow strictly with session length; only `skipped` is
bounded. `DELETE FROM` appears nowhere in the module.

## Adversarial campaign against v0.1 — what held

- **Crash consistency: 9 crash points, 0 hybrid states.** Every restart landed
  on exactly the old or the new state. This is the strongest positive result and
  the bar an Arcium implementation should be held to.
- **Concurrency: 5 scenarios clean** — same ciphertext to two workers, two
  distinct ciphertexts, two sends from one generation, retry racing send,
  duplicate ACK. One application, one commit, one artifact, one success each.
- **Reorder differential: no semantic divergence** between `M1,M2` and `M2,M1`.
- **Peer-side rollback rejected** in all three directions tested.

Two of the reviewer's own tests were mis-specified and produced false signals
before correction (a threshold compared against an unrelated limit; a probe run
below the skipped-key lifetime so a legitimate late delivery looked like a
replay). Both were rewritten, not retuned. Record such corrections.

## v0.3 — independently reproduced

27/27 passed, 48.084 s, exit 0, on a materially different stack (Python 3.11.15
vs 3.12.14, sqlite 3.45.1 vs 3.53.1, `cryptography` upgraded to 46.0.0 because
`AESGCMSIV` is unavailable below 42). The three v0.1 counterexamples run as
**positive controls** and still reproduce.

Design points worth carrying: `AESGCMSIV` for the at-rest checkpoint
(nonce-misuse-resistant, a deliberate answer to C-01); `MAX_GROUP = 32`;
`SKIP_AGE = 128` measured in successful receives, not wall-clock; two-phase
`reserve`/`commit` with a capability token and CAS.

## Declared negative results — not solved

The package states these itself; do not report them as closed.

- **Joint rollback** of endpoint *and* authority destroys the protection.
- **Cloned offline lease / sealed checkpoint** recreates a consumed generation
  and duplicate application. Random nonces would not fix application or history.
- **Retained DEK** decrypts historical snapshots; encryption at rest is achieved,
  physical erasure and storage-level forward secrecy are not.
- A **file-backed witness is not rollback-proof.** In the reviewer's own repair
  candidate, deleting the witness record while rolling the database back to
  genesis restored C-01 in full — a file store cannot distinguish "never
  existed" from "erased".

## Not measured — do not infer

Real Tor latency, battery, mobile background behaviour, power-loss/media
failure, real-device or secure-hardware behaviour, quorum operation, independent
cryptanalysis. The RPC figure (32 sends via 3 requests) is a **serialized
request count**, explicitly `NOT_MEASURED` for latency.

## Standing limits on how this may be described

- MBR is a research prototype. No formal forward-secrecy, post-compromise or
  composition proof exists.
- No comparison to Signal or any deployed messenger is supported.
- The Python reference is a **behavioural specification and a source of test
  vectors**, never production code. It stores secrets as plain hex JSON in an
  unencrypted SQLite file and performs no zeroization; Arcium encrypts its store
  and zeroizes. Port properties and tests, never the persistence layer.
