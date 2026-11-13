# Arcium Messenger

An end-to-end encrypted messenger for Android, designed with anonymity as a
goal (not yet provided; see Status). The messaging cryptography and all
message state live in a Rust core that the Android app calls through UniFFI:

- X3DH key agreement and the Double Ratchet (`crates/core-crypto`,
  `crates/core-protocol`);
- an encrypted SQLite store, each value sealed with XChaCha20-Poly1305
  (`crates/core-storage`);
- an untrusted store-and-forward relay for end-to-end encrypted envelopes
  (`crates/relay`).

Private contact discovery is a separate component: private set intersection
(PSI) on Arcium MPC, built as a Solana Anchor program and an Arcis circuit in
`arcium-psi/`.

## Status (2026-11-14)

- Messaging between devices goes through the development relay
  (`crates/relay`, binary `arcium-relay`): in memory, no TLS, no
  authentication. There is no production relay. Only debug builds accept a
  relay address (`DEV_RELAY_ALLOWED` in `android/app/build.gradle.kts`;
  `android/app/src/main/kotlin/com/arcium/messenger/messaging/RelaySettings.kt`),
  so a release build cannot send or receive messages.
- Messages sync only while the app is open; nothing arrives while it is
  closed (`MainActivity.kt`, and "Not provided" in `SettingsScreen.kt`).
- Contacts are added by exchanging contact cards out of band and comparing
  their fingerprints.
- Tor is not wired: `crates/core-transport` exists, but nothing calls it
  (finding F-15).
- The PSI program is not deployed (its program ID is a placeholder, F-14),
  has open findings (F-4), and the app does not call it.
- There is no release signing.

## Where things live

- `crates/` — the Rust workspace: crypto, protocol, encrypted storage, the
  unwired Tor transport, the UniFFI layer for Android (`mobile-ffi`), the
  relay.
- `android/` — the Kotlin and Jetpack Compose app; see `android/README.md`.
- `arcium-psi/` — the PSI Anchor program, Arcis circuit and TypeScript tests.
- `docs/` — specifications, the findings tracker, reviews, the deploy
  checklist.
- `vendor/` — a patched third-party crate; see `vendor/README.md`.
- `.github/` — CI workflows and the action that builds the Android native
  bridge.

Specifications: `docs/NET-MESSAGING.md` (messaging between devices and the
relay) and `docs/S2-B2-DURABLE-MESSAGING.md` (durable messaging lifecycle).
Security findings are tracked in `docs/SECURITY-FINDINGS.md`.

## Checks

As run by CI (`.github/workflows/arcium-ci.yml`):

```bash
cargo test --workspace --locked
cargo clippy --workspace --locked -- -D warnings
```

TypeScript side (after `npm install` in `arcium-psi/tests`):

```bash
cd arcium-psi/tests && npx tsc --noEmit
cd arcium-psi/tests && npx mocha --require ts-node/register 'src/crypto.test.ts'
```

CI also builds the PSI program and runs its localnet MPC tests
(`arcium build`, `arcium test`), and builds and tests the Android app; those
jobs need the toolchains set up in their workflows under `.github/workflows/`.
