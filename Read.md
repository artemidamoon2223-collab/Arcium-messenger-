# Arcium Messenger

Anonymous Android messenger built on:

- **Tor onion services** for transport — no central server, IP addresses hidden by Tor.
- **X3DH + Double Ratchet** for end-to-end encryption (Signal-style).
- **Arcium MPC** (later phase) for private contact discovery.

Core in Rust → exposed to Android via UniFFI → Kotlin UI in Android Studio.

## Current status (v0.1 — `core-crypto` only)

- [x] Double Ratchet, Signal spec, with skipped keys indexed by `(DH_pk, n)` for out-of-order delivery across chain transitions.
- [x] X3DH initial key agreement with signed prekey + optional one-time prekey.
- [x] AEAD (XChaCha20-Poly1305) with header bound via AAD.
- [x] Test suite covering: basic exchange, symmetric chain, DH ratchet, out-of-order within chain, late delivery across chain transition, tampered header, bad signed prekey signature.
- [ ] `core-transport` — Tor integration via `arti`.
- [ ] `core-storage` — encrypted SQLite via `rusqlite` + libsodium secretstream.
- [ ] `core-protocol` — session manager, message router, prekey bundle distribution.
- [ ] `mobile-ffi` — UniFFI bindings for Android.
- [ ] `android/` — Android Studio project (Kotlin UI).
- [ ] Arcium integration: Anchor program for PSI contact discovery.

## Build & test

```sh
rustup toolchain install stable
cd arcium-messenger
cargo test -p core-crypto
```

Expected: all 8 tests pass.

## Project layout

```
arcium-messenger/
├── Cargo.toml                  # workspace manifest, shared deps
├── README.md
└── crates/
    └── core-crypto/
        ├── Cargo.toml
        └── src/
            ├── lib.rs          # re-exports + tests
            ├── ratchet.rs      # Double Ratchet
            └── x3dh.rs         # X3DH handshake
```

## Why this layout for Android

Pure Rust crate with no I/O — easy to compile for `aarch64-linux-android`, `armv7-linux-androideabi`, etc. UniFFI later generates the Kotlin bindings automatically; Android Studio imports the resulting `.aar` and `core-crypto` becomes just `import com.arcium.messenger.crypto.*` on the Kotlin side.

## Differences from the Python prototype

The prototype this is based on had three issues that this Rust version fixes:

1. **Chain keys mismatched after DH ratchet step.** Both peers were deriving send/recv chains with the same HKDF labels, so the first message after any DH rotation could not be decrypted. Fixed by following the Signal spec exactly: receive-side derives new CKr first from `DH(old DHs, new DHr)`, then generates a new DHs and derives new CKs from `DH(new DHs, new DHr)`.
2. **Skipped keys were cleared on chain transition.** Late messages from the previous chain became undecryptable. Fixed by indexing skipped keys as `(their_dh_pk, n)`, so they survive across chains.
3. **Header was not authenticated.** Counter and DH key were transmitted alongside the ciphertext but not bound to it. Fixed by including the header bytes in the AEAD AAD.