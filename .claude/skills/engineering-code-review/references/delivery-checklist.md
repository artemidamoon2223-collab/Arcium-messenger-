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
```

The first three commands are the ones `.github/workflows/arcium-ci.yml` runs;
`.devcontainer/setup.sh` prints `cargo test --workspace` as its quick-start.
Running them locally is the cheapest way to know what CI will say.

## Which CI checks a diff actually triggers

Knowing this prevents both false confidence and pointless waiting.

- `bridge-compile-package` (`.github/workflows/android-native-bridge.yml`)
  fires on `crates/**`, the repository-root `Cargo.toml`,
  `android/app/build.gradle.kts`, and its own workflow file. It does **not**
  fire on docs-only diffs, and it does **not** fire on changes confined to
  `arcium-psi/`.
- `arcium-build` and `arcium-test` (`.github/workflows/arcium-ci.yml`) run on
  every push and pull request.

## Reading the result honestly

- A green check means the job reached its end, nothing more.
- `arcium-build` and `arcium-test` currently end on a zero-exit path even when
  the underlying command fails, so their colour is not a pass signal. Read the
  job log. This is tracked as F-11 in `docs/SECURITY-FINDINGS.md`.
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
