### Karpathy Code Review

Reviewed both changed files against the four principles.

#### ✅ Think Before Coding
`src/gate.py:10-24` validates only fields the workflow defines.

---

**KARPATHY_REVIEW_RESULT**
complete: **yes**
files: `src/gate.py`, `docs/review.md`
think_before_coding: pass | src/gate.py:10-24 checks exactly the fields the workflow prompt defines
simplicity_first: pass | one parser function per concern; no configuration layer (src/gate.py:30-58)
surgical_changes: warning | docs/review.md:3 rewords an unrelated sentence next to the new section
goal_driven: pass | tests/test_gate.py:12-40 cover each rejection; not executed by this reviewer
unverified: the PR body says the tests pass; I did not run them
summary: The change does what it states with one small out-of-scope doc edit.
**KARPATHY_REVIEW_END**

---

**Job run**: [View job](https://github.com/example/example/actions/runs/1)
**Branch**: `ci/example`
