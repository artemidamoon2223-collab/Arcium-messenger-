---
name: qc-investigate
description: "Reproducible bug investigation for Arcium: reproduce first on the unfixed base, with deterministic seeds and bounded execution, minimise the counterexample, classify it (known tracker finding, new reproduction, missing coverage, environment), and hand a failing-on-base regression criterion to qc-spec. Use when a defect, a failing test or a suspicious behaviour must be pinned down before anyone fixes it. Fixing is a separate Owner task; this skill authorizes nothing."
disable-model-invocation: true
argument-hint: "<symptom or finding id>"
---

# qc-investigate — reproduce before you explain, explain before you fix

This skill authorizes nothing. It produces evidence and a regression
criterion; a fix needs its own Owner instruction, and a cryptographic or
protocol fix always does (`CLAUDE.md`, «Обращение с криптокодом»).

## Steps

1. **Fix the target.** Record the exact commit SHA. Work in a disposable
   clone (`repo-change-protocol` §2). Probes stay out of the repository
   unless the Owner asks for them.
2. **Check what is already known.** Search `docs/SECURITY-FINDINGS.md` and
   the existing tests for the symptom. A known finding is cited by its id,
   not rediscovered; re-derive its status from source at the target SHA.
3. **Reproduce.** Write the smallest test that shows the symptom, with:
   - a fixed seed for every schedule, ordering or input choice (print it);
   - a bound on every loop, retry and wait, and a `timeout`;
   - an assertion of the *expected* invariant, so that the run fails while
     the bug is present.
   Run it on the unfixed base. If it does not fail there, it does not
   reproduce the bug: say so and keep investigating, do not tune the
   expectation to the result (`mbr-integration`, «Evidence discipline»).
4. **Minimise.** Shrink inputs and steps while it still fails. Keep the
   seed, the command and the failing output tail.
5. **Explain.** Point to the cause by `path:line` at the target SHA
   (SOURCE_VERIFIED), separate from what the run showed (RUNTIME_VERIFIED)
   and what you infer (INFERRED). For a security-relevant cause, describe the
   attacker path as `arcium-security-review` step 5 requires, and rate it
   with that skill's severity scale.
6. **Classify** each result as exactly one of: known finding (tracker id),
   newly reproduced consequence of a known finding, new finding, missing
   coverage (behaviour correct, no test), environment limit.
7. **Hand over.** Give the Owner the reproduction command, seed, output tail
   and classification. If a fix is authorized, the reproduction becomes a
   `qc-spec` criterion that must fail on `base` and pass after the fix.

Environment limits are results too: a missing toolchain, a blocked host or
an absent device is reported as `NOT_VERIFIED` with what would verify it.
