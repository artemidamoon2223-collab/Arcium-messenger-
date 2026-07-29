# Repository map

Orientation only. **This file is derived from the repository and will drift.**
It is kept here, out of always-loaded context, precisely so that a stale copy
cannot be read into every session as ground truth — the defect tracked as F-17
in `docs/SECURITY-FINDINGS.md`.

Re-derive rather than trust:

```bash
ls -1                                  # top level
ls -1 crates/                          # Rust workspace members
find crates -name '*.rs' | sort        # Rust sources
ls -1 .github/workflows/               # CI
```

If anything below disagrees with those commands, the commands are right.

## Two separate cargo workspaces

This is the single most important structural fact, and the easiest to get
wrong.

- The **repository-root `Cargo.toml`** is a workspace whose members are the
  crates under `crates/`. It governs `crates/**`, including the `mobile-ffi`
  cdylib that becomes the Android `.so`.
- **`arcium-psi/Cargo.toml` declares its own `[workspace]`.** The root manifest
  does not include it. `arcium build` and `arcium test` run with
  `working-directory: arcium-psi`, so cargo resolves the workspace root *there*
  and never reaches the repository root.

Consequence: profile settings that `arcium build` demands (for example
`overflow-checks`) belong in `arcium-psi/Cargo.toml`. Putting them in the root
manifest changes the shipped Android `.so` and does not affect `arcium build`
at all.

### Pre-devnet stub in the PSI client

`arcium-psi/tests/src/program.ts` sets `const lutOffset = new BN(0)` as a
placeholder. Before a real devnet deploy it must be replaced by reading the MXE
account's lookup-table offset field, which is named **`lutOffsetSlot`**. A
comment in `arcium-psi/tests/src/scenarios.test.ts` names it `lutLastSlot`,
which is wrong — do not copy that name forward. Verify both line numbers before
citing them; they drift.

## Top level

| Path | What it is |
|------|-----------|
| `crates/` | Rust core: crypto, storage, transport, protocol, FFI |
| `arcium-psi/` | Anchor program, Arcis circuit, TypeScript tests — separate workspace |
| `android/` | Kotlin/Compose app, Gradle build, generated UniFFI bindings |
| `docs/` | Security findings tracker, deep review, home-deploy guide |
| `.github/` | Workflows and the composite UniFFI bridge action |
| `.devcontainer/` | Codespaces setup (no Android SDK/NDK) |

## Rust crates

| Crate | Role |
|-------|------|
| `core-crypto` | X3DH, Double Ratchet, hybrid KEM, contact hash, RescueCipher stub |
| `core-storage` | Encrypted SQLite key-value store |
| `core-transport` | Tor client (arti) |
| `core-protocol` | Session manager over the ratchet |
| `mobile-ffi` | UniFFI cdylib, `[lib] name = "arcium_core"` → `libarcium_core.so` |

Crypto layering rules for these crates are in `CLAUDE.md` and are not repeated
here.

## Documents worth knowing

- `docs/SECURITY-FINDINGS.md` — authoritative current status for every finding
  (F-1 … F-17, plus X-series). A tracker update is always a separate PR from
  the fix, and lands after it.
- `docs/SECURITY-REVIEW-2026-06-deep.md` — historical snapshot of the 2026-06
  review, kept for the original finding definitions. Its status language is
  superseded by the tracker.
- `docs/HOME-DEPLOY.md` — devnet deploy, which needs open network and toolchain
  the agent sandbox does not have.
- `PROJECT_CONTEXT.md` — PSI architecture detail at the repository root.
