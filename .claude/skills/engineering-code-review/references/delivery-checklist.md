# Pre-delivery checklist

Run this before reporting a task done. Do not close a task without an explicit
verification step — "it looks right" is not one.

## Minimum

```
☐ cargo test --workspace --locked                    →  0 упавших
☐ cargo clippy --workspace --locked -- -D warnings   →  0 предупреждений
☐ tsc --noEmit                              →  0 ошибок  (если трогал TS)
☐ grep на висячие ссылки                    →  нет
☐ diff затрагивает ТОЛЬКО запрошенное       →  да
☐ инженерное ревью (karpathy-review.md)     →  блок результата в отчёте
☐ security-ревью, если diff чувствителен    →  блок arcium-security-review в отчёте
```

The first three commands are the ones `.github/workflows/arcium-ci.yml` runs
(the two cargo commands there with `--locked`, so a missing or stale
`Cargo.lock` fails instead of being re-resolved);
`.devcontainer/setup.sh` prints `cargo test --workspace` as its quick-start.
Running them locally is the cheapest way to know what CI will say.

A new source file that holds keys, a wire format, an identity or a stored
record gets only its directory's QC classes (`.claude/qc/qc.py`, `RULES`):
in `crates/mobile-ffi/src/` that is FFI alone, with no owner gate. Give it a
rule of its own and a line in `EXPECTED` of
`.claude/qc/tests/test_qc_rules.py`. CI's qc-unit job fails for a code
file (not a test) whose code names this project's crypto API, a crypto
primitive, key type, key store or wire-format version (`CRYPTO_CODE_RE`,
`PROTOCOL_CODE_RE`; names only, so not every crypto use) and that no
owner-gated rule covers; until it has one, `qc.py classify` classes such a
change by its contents. Renaming or removing a file a rule names fails
`qc.py self-test` in CI until the rule follows.

## Which CI checks a diff actually triggers

Knowing this prevents both false confidence and pointless waiting. This is the
one copy of the path filters in the skills; other skills point here. It is
derived from the `on:` block of every file in `.github/workflows/` (the path
lists at `de328a1`; `push` limited to `main` by #233). Those blocks are
the source: re-derive at your target SHA with

```bash
grep -nE "^  (push|pull_request|schedule|workflow_dispatch):|^    branches:|^      - '" .github/workflows/*.yml
```

| workflow | runs on a pull request, and on a push to `main`, when the diff touches |
|---|---|
| `arcium-ci.yml` | anything (no path filter) |
| `android-ci.yml` | `android/**`, its own file |
| `android-native-bridge.yml` | `crates/**`, `Cargo.toml`, `Cargo.lock`, `vendor/**`, `android/app/build.gradle.kts`, its own file |
| `android-instrumentation.yml`, `android-two-device-e2e.yml` | `crates/**`, `Cargo.toml`, `Cargo.lock`, `vendor/**`, `android/**`, `.github/actions/uniffi-android-bridge/**`, its own file |
| `android-build-baseline.yml`, `native-artifact-baseline.yml` | never: manual (`workflow_dispatch`) only |
| `monthly-backup.yml` | never: monthly schedule and manual only |

- A push to any other branch, or of a tag, runs nothing (`branches: [main]`
  under `push`):
  a branch is checked by the `pull_request` run once it has a pull request,
  and that run's check runs are reported on the head commit. GitHub does not
  start a `pull_request` run while the pull request has a merge conflict.
  `workflow_dispatch` still runs a workflow on any branch.
- Each filtered workflow uses the same list for `push` and `pull_request`.
  For a pull request the list is matched against the whole pull request's
  diff from its base, not only the last push.
  `Cargo.toml` and `Cargo.lock` match the repository-root files only; crate
  manifests are under `crates/**`.
- A docs-only or `.claude/`-only diff triggers **only** `arcium-ci.yml`, and so
  does a change confined to `arcium-psi/`.
- A change confined to `.github/actions/uniffi-android-bridge/**` triggers the
  two emulator workflows and `arcium-ci.yml`, but not `android-native-bridge.yml`
  or `android-ci.yml`, although both call that action.
- So a documentation PR that is green shows that the deterministic Rust and
  Arcium jobs still pass on that tree. It says nothing about the Android
  jobs, which did not run.

## Reading the result honestly

- A green check means the job reached its end, nothing more. Whether that end
  means "the commands passed" depends on how the job handles exit codes: read
  the step, and for a claim that matters, the log.
- A `|| true`, `continue-on-error: true` or piped command is a problem only
  when it sits on a step the job depends on for its verdict. Decide by what
  the step gates:
  - **Diagnostic** — the step gates nothing: printing tool versions, or an
    `if: failure()` log dump after the real step has already failed the job.
    `|| true` there is fine and is not a finding.
  - **Masked gate** — the step is the required build, test, lint or audit
    itself, and its non-zero exit is swallowed, or a pipe (`cmd | tee`) hides
    it because `pipefail` is off. That makes the job's colour meaningless, and
    it is a finding. Turning a blocking check into an advisory one is
    forbidden (`CLAUDE.md`, «Ревью и CI»).
- At the time of writing `arcium-ci.yml` fails the job on a non-zero exit of
  `arcium build` and of `arcium test` (the latter under `set -o pipefail`, with
  guards for "no passing test" and "pending tests"); its remaining `|| true`
  are diagnostics. That describes one commit: F-11 in
  `docs/SECURITY-FINDINGS.md` records the state and the SHA it was read at.
  Re-check the workflow at yours, and do not carry either "CI swallows
  failures" or "CI is trustworthy" from this file to a different tree.
- If a check is stuck rather than failing, that is an infrastructure condition,
  not a result. Do not treat it as either pass or fail.

## Where a new test goes

- **Rust:** next to the tests of the same code; follow the neighbours. Small
  unit tests sit in a `#[cfg(test)] mod tests` block at the end of the file
  they cover. Larger crates keep test files apart:
  `crates/mobile-ffi/src/tests/*.rs` (declared in `src/tests/mod.rs`, the
  `#[cfg(test)] mod tests;` of `crates/mobile-ffi/src/lib.rs`),
  `crates/mobile-ffi/src/network/tests.rs` (the `mod tests;` of
  `network.rs`), `crates/core-protocol/src/messaging/tests/*.rs`
  (declared in `messaging/tests.rs`, the `#[cfg(test)] mod tests;` of
  `messaging.rs`), and `crates/relay/src/v2_tests.rs`, a sibling file
  (`mod v2_tests;` in `relay/src/lib.rs`). Cargo integration tests are in
  `crates/<crate>/tests/` where one exists (`crates/core-crypto/tests/`). Re-derive with
  `find crates -path '*tests*' -name '*.rs' | sort`.
- **TypeScript:** `arcium-psi/tests/src/*.test.ts`, run with
  `npx mocha --require ts-node/register 'src/<name>.test.ts'` from
  `arcium-psi/tests`.

Do not add a test-count total to `CLAUDE.md` or to any always-loaded document —
counts drift, and that is finding F-17.

## Mutation check (fix PRs)

A fix PR names the mutations it was checked against: each a small source
change that brings the defect back or breaks one rule of the fix, and each
must make a named test fail. The PR lists every mutation with the test that
caught it; one that nothing catches is a missing test, not a pass.

- Run mutations in the disposable copy (`repo-change-protocol` §2), never in
  the persistent checkout: a mutation edits a source file while it runs, and
  an interrupted run leaves it there.
- One at a time: apply it as an exact text replacement that must match once,
  run the tests that should catch it, then restore the file byte for byte
  from a saved copy and confirm `git status` is clean before the next one.
- Caught means: it compiled, the run failed, and the failure is a test that
  should catch it, read from the `test … FAILED` or `panicked at` lines. A
  compile error, a timeout or a failure somewhere else is not a catch.
- Output of tests running in parallel can interleave, so a script that
  parses test names can miss one. On a failed run with no name found, run
  that mutation alone again and read the output.

## If a step cannot be run

Say which step, and why it could not run — missing network, missing toolchain,
missing permission. Do not substitute a weaker check and describe it as the
verification. Do not infer the answer from indirect signals.
