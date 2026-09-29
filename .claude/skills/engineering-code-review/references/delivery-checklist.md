# Pre-delivery checklist

Run this before reporting a task done. Do not close a task without an explicit
verification step — "it looks right" is not one.

## Minimum

```
☐ cargo test --workspace                    →  0 упавших
☐ cargo clippy --workspace -- -D warnings   →  0 предупреждений
☐ tsc --noEmit                              →  0 ошибок  (если трогал TS)
☐ grep на висячие ссылки                    →  нет
☐ diff затрагивает ТОЛЬКО запрошенное       →  да
☐ инженерное ревью (karpathy-review.md)     →  блок результата в отчёте
☐ security-ревью, если diff чувствителен    →  блок arcium-security-review в отчёте
```

The first three commands are the ones `.github/workflows/arcium-ci.yml` runs;
`.devcontainer/setup.sh` prints `cargo test --workspace` as its quick-start.
Running them locally is the cheapest way to know what CI will say.

## Which CI checks a diff actually triggers

Knowing this prevents both false confidence and pointless waiting. The `on:`
blocks of the workflows are the source; re-read them at your target SHA, this
list is a pointer and can go stale.

- `arcium-ci.yml` runs on every push and pull request (no path filter). A
  docs-only or skill-only diff triggers **only** this workflow.
- The Android workflows are path-filtered. `android-native-bridge.yml` fires on
  `crates/**`, the repository-root `Cargo.toml`, `android/app/build.gradle.kts`
  and its own file; `android-instrumentation.yml` and
  `android-two-device-e2e.yml` fire on `crates/**`, `Cargo.toml`, `android/**`
  and their own inputs; `android-ci.yml` fires on `android/**`. None of them
  fires on a docs-only diff, and none fires on a change confined to
  `arcium-psi/`.
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

- **Rust:** a `#[cfg(test)] mod tests { ... }` block at the end of the crate
  file it covers.
- **TypeScript:** `arcium-psi/tests/src/*.test.ts`, run with
  `npx mocha --require ts-node/register 'src/<name>.test.ts'` from
  `arcium-psi/tests`.

Do not add a test-count total to `CLAUDE.md` or to any always-loaded document —
counts drift, and that is finding F-17.

## If a step cannot be run

Say which step, and why it could not run — missing network, missing toolchain,
missing permission. Do not substitute a weaker check and describe it as the
verification. Do not infer the answer from indirect signals.
