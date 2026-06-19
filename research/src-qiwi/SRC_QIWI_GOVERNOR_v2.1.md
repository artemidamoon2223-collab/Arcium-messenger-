# SRC/QIWI Research Governor v2.1 — Specification

## 0. What Changed from v2 (and what did not)

v2.1 adds no capability. It draws boundaries v2 assumed but never stated, on points an adversarial review found undefined or self-contradictory. Every change is a clarification of an existing invariant. The system is the same governor; v2.1 only says where its lines are.

## 1. System Purpose

Prevent unsupported belief updates, and legitimize stopping when evidence is exhausted. Both halves co-equal. The system governs claim-state; it does not produce conclusions. It reacts to declared inputs; it never initiates.

## 2. The Generate/Validate Boundary (operational definition)

This is the spine of the system, and v2 left it as an assertion. v2.1 defines it operationally:

> The system *generates* a value if and only if, in the absence of any human declaration for that field, its output would still populate that field with a substantive value. The system *validates* if and only if its only outputs are accept, reject, or a reject-reason — never a substantive field value the human did not supply.

Consequences that follow directly:
- A yes/no check on a human-supplied value is validation.
- A default value is generation — supplying a field the human left blank is exactly the forbidden act. (This is why Section 4 removes the provenance default.)
- A reject-reason that enumerates allowed values is the single permitted micro-exception: it returns no substantive judgment, only the closed vocabulary against which the human's future declaration will be checked. It states the menu; it does not choose from it.
- Anything that ranks, proposes, fills, infers, or selects on the human's behalf is generation and is out of class.

The meta-invariant, restated with this definition: the system validates judgments humans declare; it never generates them — where "generate" is defined above.

## 3. Actor Model

- **Operator** — declares Sources, Observations, and prediction transitions (with citations). Supplies research-layer judgments. May not close governance questions.
- **Owner** — makes Governance Decisions; sole authority that closes a governance question. Owner and operator may be the same person, but the roles are distinct, and a governance decision is valid only when recorded under the owner role.
- **Governor** — the system itself. Validates, records, rejects, pauses. Holds no role that declares or decides; it only checks declarations and decisions made by the other two.

Knowledge/power separation is enforced at the actor level: research judgments come from the operator, authority judgments from the owner, and the Governor generates neither.

## 4. Provenance Model (default removed)

Closed set: observed / derived_empirical / derived_analytical / governance_decision.

No default. Provenance has no default value. A record with absent provenance is rejected, not filled. A silently-defaulted "observed" on a forgotten "derived_analytical" is a fabricated provenance, the system's worst failure; absence must be loud.

- Who assigns: the operator (or, for governance_decision records, the owner), at creation.
- What the Governor validates: presence, closed-set membership, and non-collapse (an analytical derivation is never relabeled observed).
- What the Governor must never do: infer, guess, classify, fill, or default the provenance.
- conditionally_analytical marker: assigned by the declaring human, never by the Governor. The Governor does not evaluate whether a derivation is framing-dependent (Interpreter behavior); it only records and validates the human's marker.
- Multi-origin records: if a record's true origin is mixed, the human declares the primary provenance and may note secondary origins in a descriptive field; the Governor does not adjudicate which origin dominates.

## 5. Core Record Types

- **Source** — id, type, locator, timestamp, persistence_level, status (FOUND | [SOURCE NOT FOUND]).
- **Observation** — id, statement, source_ids[], confidence, created_at, provenance_type (no default). Optional: caveats, secondary_origins (descriptive).
- **Prediction** — id, question_id, claim, status, observation_ids[], four pre-registered conditions (strengthened/weakened/falsified/unknown), history (append-only), last_updated.
- **Governance Decision** — decision_id, owner, date, decision, reason. Retrospective only. See Section 7 for its dual nature.
- **Evidence Ceiling** — question_id, exhausted_source_categories, remaining_required_source (descriptive-only, see Section 6), reason_inaccessible, created_at.

All belief-bearing records require provenance; none defaults it.

## 6. Move Conditions and Evidence Ceilings

Move conditions are audit/integrity support, not semantic proof. v2 called this "enforcement," overclaiming. v2.1 states plainly:

> The move-condition check verifies that the operator (a) cited existing observation IDs and (b) reproduced the exact pre-registered condition text. It proves the operator referenced and recorded; it does not prove the observation supports the claim. It is integrity-support for an honest operator and an audit trail for review — not a defense against a careless or motivated operator, who can pair a correct citation with an irrelevant observation and pass. Semantic adequacy is verified by human review, never by the Governor (which would be Interpreter drift).

Valid states: pending, supported_weak, supported, weakened, falsified, unknown. Transition: non-empty existing observation_ids + non-empty pre-registered target condition + exact-text citation. Audit: immutable history entry per transition.

Evidence Ceilings. A ceiling blocks creation of new observations from inaccessible sources for its question_id; it never invalidates recorded observations nor forbids applying existing ones (apply them before recording the ceiling).

- remaining_required_source is descriptive-only. It is a human note naming what would resolve the ceiling. It is never an actionable target: the Governor does not surface it, rank it, aggregate it across ceilings, or treat it as a to-do. Reading these fields into a list of sources-to-acquire would be Planner behavior and is out of class.
- Ceiling lifecycle: a ceiling is lifted only when a human declares a genuinely new source category and records the lift as an explicit event. Whether a given lift is a research event (operator) or requires owner judgment is itself declared by the human; the Governor does not decide when a ceiling should lift.

## 7. Governance Model — decision-as-authority vs decision-as-fact

v2 asserted governance decisions "never appear as an observation," yet defined them isomorphically to a sourced fact. v2.1 splits the two senses:

- **Governance Decision as authority** — the act that closes a governance question. In this sense it is never an observation and never backs a research prediction. Only the owner produces it; it lives in the Governance Decision log.
- **Governance Decision as observed fact** — the statement "the owner decided X on date Y" is a true, sourced, dated fact about the world, and may be recorded as an Observation (provenance observed, source = the decision record) when the research layer legitimately needs to reason about it descriptively.

The separation is therefore not "these records may never relate," but: the decision's authority never flows into the research layer; the decision's factuality may, as an ordinary sourced observation. A governance question still has no move condition and is closed only by an owner decision; the unresolved state before that decision is stable and correct, not a gap.

## 8. Correction and Retraction (append-only)

v2 was silent on deletion; real systems rot here. v2.1 defines correction as append-only, never destructive:

- No record is deleted or edited in place. A Correction record (id, target_record_id, corrected_fields, reason, actor, date) supersedes a prior record; both remain in the store.
- A Retraction record (id, target_record_id, reason, actor, date) marks a record withdrawn. A retracted Observation remains visible but flagged; predictions that cited it retain their history (the transition happened) and are flagged as resting on a retracted observation, for human re-review. The Governor does not auto-revert the prediction — auto-reverting would be the Governor generating a status change, which Section 2 forbids.
- Corrections and retractions are themselves provenance-bearing and actor-attributed, subject to the same validation as any record.

This preserves the meta-invariant under change: the audit trail only grows, and no judgment is silently rewritten or auto-generated.

## 9. Minimal Governor Boundary

Responsibilities: validate, record, reject, pause. Non-goals (each out of class): planning, tool routing, source acquisition, autonomous search, goal/agenda management, action execution. Boundary test: does it strengthen claim-state governance, or introduce generation/initiation/planning/interpretation? — where "generation" has the Section 2 operational definition. The latter is rejected.

## 10. Storage Independence (claim corrected)

The spec names records, fields, relationships, invariants — never a mechanism. But v2 overstated uniformity. v2.1 corrects it:

> Invariant enforcement strength is not uniform across backends. Closed-set fields are enforced at the type level in a backend that has sum types (e.g. Rust enums) and only by runtime validation in one that does not (Markdown, plain SQL). The guarantee (no out-of-set value persists) holds in both, but by different means. A specification-conformant backend must therefore supply a runtime validator wherever the type system cannot structurally exclude invalid values.

Two universal constraints any backend honors: closed-set fields stay closed (by type or by runtime check), and history/corrections are append-only and immutable. Nothing in Sections 2–9 presumes a language, format, or single node.

## 11. v2.1 Minimal Kernel

Unchanged in size from v2; the corrections are clarifications, not additions:

1. Five record types as typed structures, closed-set fields enforced by type or runtime check, no defaults on provenance.
2. One pure validator per invariant: provenance-presence-and-membership, move-condition citation gate, ceiling-consistency, governance-separation, actor-authority (operator vs owner).
3. Append-only history, plus append-only Correction/Retraction records.
4. A persistence adapter behind the record definitions (swappable store).
5. Self-test proving: unsupported transition rejected; wrong-condition rejected; correct observation+citation accepted; ceiling blocks only its question_id; [SOURCE NOT FOUND] recorded; missing provenance rejected; operator cannot close a governance question; retracted-observation prediction flagged, not auto-reverted.

The kernel remains all validation, zero generation — now with "generate" operationally defined, so the boundary is checkable rather than assumed.
