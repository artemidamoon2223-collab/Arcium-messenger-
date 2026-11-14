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
| `crates/` | Rust core: crypto, storage, transport, protocol, FFI, relay |
| `arcium-psi/` | Anchor program, Arcis circuit, TypeScript tests — separate workspace |
| `android/` | Kotlin/Compose app and Gradle build; the UniFFI bindings are generated into its build directory, not committed |
| `vendor/` | Vendored crates patched into the root workspace through `[patch.crates-io]` and excluded from its members (`tor-dirmgr`; why and when to remove it: `vendor/README.md`) |
| `docs/` | Findings tracker, specifications, the 2026-06 deep review, operating guides |
| `.github/` | Workflows, their helper scripts, and the composite UniFFI bridge action |
| `.devcontainer/` | Codespaces setup (no Android SDK/NDK) |

## Rust crates

| Crate | Role |
|-------|------|
| `core-crypto` | X3DH, Double Ratchet, hybrid KEM, handshake-refusal MAC, contact hash with E.164 normalization, RescueCipher stub |
| `core-storage` | Encrypted SQLite key-value store |
| `core-transport` | Tor client (arti); no production caller yet (F-15) |
| `core-protocol` | Durable sessions over the ratchet: staged transitions with a conditional commit, the outbox and inbox, session removal (S2-B2) |
| `mobile-ffi` | UniFFI cdylib, `[lib] name = "arcium_core"` → `libarcium_core.so`; `src/network.rs` is `NetworkMessenger`, the app's sync and chat path over the relay; `src/network/chat.rs` is the per-contact history |
| `relay` | Untrusted store-and-forward relay: wire protocol, client, and the `arcium-relay` server binary (dev: no TLS, no client authentication) |

Crypto layering rules for these crates are in `CLAUDE.md` and are not repeated
here.

## Documents worth knowing

- `docs/SECURITY-FINDINGS.md` — a dated snapshot of finding status: the
  F-series, A-series, H-series follow-ups, X-series, the R-series (from the
  architecture review of 2026-11-10 and later reviews, in "Update 2026-11-12"
  and later sections), the
  D-numbered leads D-007 … D-011 (from "Reconciliation 2026-11-06", some with
  rows in later updates) and scope notes (N-). Each section names the `main`
  commit it was read at; it is a list of leads, not a live source: re-check a
  row against the source at your own target SHA. A tracker update is always a
  separate PR from the fix, and lands after it (`repo-change-protocol` §9).
- `docs/SECURITY-REVIEW-2026-06-deep.md` — historical snapshot of the 2026-06
  review, kept for the original finding definitions. Its status language
  reflects 2026-06-09 and is not current.
- `docs/S2-B2-DURABLE-MESSAGING.md` — the durable messaging lifecycle: staged
  ratchet transitions, outbox and inbox, recovery after an unknown commit
  outcome.
- `docs/NET-MESSAGING.md` — network messaging over the relay, built on S2-B2:
  the relay protocol, `NetworkMessenger`, and the documented limits.
- `docs/RECONCILIATION-2026-11-06-PROBES.md` — the code, commands and output
  of the temporary probes behind "Reconciliation 2026-11-06" in the tracker.
  Not part of the test suite.
- `docs/QC-V1-OPERATIONS.md` — how the owner turns the QC V1 guards on for a
  clone, ends a loop, and recovers when a guard blocks work. Off by default.
- `docs/HOME-DEPLOY.md` — devnet deploy, which needs open network and toolchain
  the agent sandbox does not have.
