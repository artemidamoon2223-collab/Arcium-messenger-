# Autonomous Research Agent Specification v1.0

## Purpose

The Agent layer is the system that lives above the SRC/QIWI Research Governor and acts as its client. Its purpose is to do the work the Governor deliberately refuses to do — plan, search, collect evidence, decompose questions, manage tasks, and execute bounded actions — while never itself deciding what is admissible or true. The Governor governs claim-state; the Agent feeds it candidates. The Agent exists so that research can be conducted at scale without the Governor ever ceasing to be a pure validation and governance layer. The Agent may be ambitious; the Governor stays minimal; the boundary between them is the point of the design.

---

## Constitutional Principle

> **Agent proposes. Human declares. Governor validates. Governor is the sole writer.**

This principle exists because the Governor is a citation gate, not a semantic check. It verifies that a judgment was referenced and recorded; it does not verify that the judgment is true. If an autonomous Agent were permitted to *declare* its own observations and cite its own conditions, it would pass the gate while generating unsupported beliefs at machine scale — the Governor would become a rubber stamp wearing a constitution. The principle keeps the act of *declaring a belief* in human hands, the act of *validating its admissibility* in the Governor, and the act of *proposing candidates* in the Agent. Each actor does one thing, and no actor generates the judgment another is responsible for.

---

## Architectural Invariants

### I1 — Sole Writer
- **Purpose:** ensure a single, governed mutation path to claim-state.
- **Guarantee:** claim-state is mutable only through Governor validation; the Agent has read and submit access, never direct write.
- **Violation consequence:** total failure — governance becomes theater, because beliefs can change without validation.

### I2 — Propose-not-Declare
- **Purpose:** prevent the Agent from occupying the human's declaring role.
- **Guarantee:** the Agent emits candidates; a human actor declares provenance and judges semantic adequacy; the Governor validates.
- **Violation consequence:** the citation gate is defeated — the Agent generates unsupported beliefs at scale and the Governor rubber-stamps them.

### I3 — Human Authority Boundary
- **Purpose:** reserve judgment and authority decisions to humans.
- **Guarantee:** what to pursue, what counts as evidence, semantic adequacy, provenance of non-empirical claims, ceiling recording and lifting, governance questions, goal priority, and the Agent's own autonomy bounds are never made, simulated, or defaulted by the Agent.
- **Violation consequence:** the knowledge/power separation collapses; the Agent decides things only humans may decide.

### I4 — Governor Non-Bypassability
- **Purpose:** make the Governor structurally unavoidable.
- **Guarantee:** no path exists from Agent intent to claim-state that does not pass through the Governor — the Agent cannot bypass it by construction, not merely by policy.
- **Violation consequence:** I1 is void; an unvalidated write path exists.

### I5 — Single Source of Truth
- **Purpose:** prevent divergence between the canonical record and the Agent's working state.
- **Guarantee:** the Governed Ledger is the only durable record of claim-state and history; any Agent memory is an ephemeral cache that may be destroyed without loss.
- **Violation consequence:** the Agent reasons from a stale or divergent picture, indirectly eroding the integrity I1 protects.

---

## Actor Model

- **Owner (human):** sets governance decisions, goal priority, and the Agent's autonomy bounds. Sole closer of governance questions. The only actor who may authorize what the Agent is permitted to do.
- **Operator (human):** declares Sources and Observations (assigning provenance) and proposes transitions (citing pre-registered conditions); judges semantic adequacy — the determination the Governor never makes. May not close governance questions.
- **Agent (machine, client):** plans, searches, collects evidence, decomposes questions, manages tasks, executes bounded actions. May autonomously declare only `derived_empirical` observations within owner-set bounds. Decides nothing about admissibility, truth, adequacy, pursuit, or its own authority.
- **Governor (system, fixed):** validates, records, rejects, pauses. Sole writer of claim-state. Decides only admissibility. Generates nothing.

**Authority boundaries:** research-layer declarations come from the Operator; authority-layer decisions from the Owner; admissibility from the Governor; candidate production from the Agent. No actor performs another's act.

---

## Control Flow

### Normal Research Flow
1. Owner/Operator supplies a question and the source-categories that count.
2. Agent confirms no Evidence Ceiling exists for the question.
3. Agent collects a candidate observation using a configured tool.
4. The candidate carries a real, locatable source or is discarded.
5. Operator declares provenance and judges semantic adequacy.
6. Agent submits the observation; Governor validates and records.
7. When conditions are met, Operator cites the pre-registered condition; Agent submits the transition; Governor validates and writes.
8. Loop until the question is resolved or paused.

### Rejection Flow
1. Governor returns a rejection.
2. Agent halts that claim and does not auto-retry.
3. Rejection is surfaced to the Operator and logged.
4. Work resumes only on human action.

### Type A Unknown
1. Status is analysis-limited unknown.
2. Agent may continue collecting within bounds and propose further candidates.

### Type B Unknown
1. Status is evidence-limited unknown.
2. Agent pauses that line and does not acquire the remaining required source.
3. The matter is surfaced to the Operator; work resumes only on a human-declared new source.

### Evidence Ceiling
1. Operator records a ceiling for the question.
2. Agent stops collecting new observations for it and does not route around it.
3. The ceiling is lifted only when a human declares a genuinely new source category.

### Governance Decision Required
1. A transition requires an Owner decision.
2. Hard stop: the Agent escalates to the Owner.
3. The Agent waits; it cannot make, simulate, or default the decision.
4. Work resumes only after the Owner records the decision and the Governor validates its authority.

---

## Derived-Empirical Exception

The Agent may autonomously declare an observation only when its own execution genuinely is the source, and only with provenance `derived_empirical`, within owner-set bounds. The declaration is logged with the Agent as the acting party so that audit can distinguish agent-declared from human-declared records.

**Allowed (the Agent's execution is the source):**
- benchmark execution
- latency measurement
- experiment execution

**Not allowed (these are interpretation, not measurement):**
- inferred motive
- inferred causality
- inferred explanation
- inferred intent

All provenance other than `derived_empirical` — `observed`, `derived_analytical`, and `governance_decision` — remains human-declared without exception.

---

## Agent Identity Test

The architecture remains the same architecture only if all of the following hold:

- ✓ Sole Writer preserved
- ✓ Propose-not-Declare preserved
- ✓ Human Authority Boundary preserved
- ✓ Governor Non-Bypassability preserved
- ✓ Single Source of Truth preserved

If any one fails, it is not the same architecture, regardless of what it is named.

---

## Relationship To Governor

The Agent is a client of the Governor. The Governor is not part of the Agent. The Agent may be replaced; the Governor may be reimplemented. Neither substitution changes the architectural identity, because that identity is defined by the preserved invariants, not by any implementation of either layer.

---

## What Is Not Defined

This specification does not define:

- Planner implementation
- Tool Router implementation
- Task Queue implementation
- Memory implementation
- Programming language
- Storage backend
- UI
- Deployment model

These belong to replaceable implementations and are deliberately outside the identity of the Agent layer.

---

## Preservation Statement

This document defines the identity of the Autonomous Research Agent layer independently of any implementation. It names the invariants, actors, control flows, and boundaries that any conforming Agent must preserve, and nothing about how they are built. So long as the five invariants hold and the constitutional principle stands — Agent proposes, human declares, Governor validates, Governor is the sole writer — an implementation in any language, on any storage, with any interface is a faithful instance of this architecture. When the invariants are preserved, the architecture survives; when any is lost, the artifact is something else and must not claim this identity.
