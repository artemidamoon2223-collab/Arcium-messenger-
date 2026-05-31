# Arcium Messenger — Android

Kotlin + Jetpack Compose skeleton for the anonymous E2E messenger.

## Structure

```
android/
├── app/src/main/kotlin/com/arcium/messenger/
│   ├── ArciumApp.kt          Hilt Application entry point
│   ├── MainActivity.kt       Compose + Navigation host
│   ├── ffi/
│   │   └── ArciumCore.kt     UniFFI wrapper around the Rust core library
│   ├── data/
│   │   ├── IdentityRepository.kt
│   │   ├── ContactRepository.kt
│   │   └── MessageRepository.kt
│   ├── ui/
│   │   ├── theme/            Material 3 dark theme (Color, Type, Theme)
│   │   ├── navigation/       AppNavigation.kt — all routes
│   │   ├── onboarding/       Generate identity keys
│   │   ├── contacts/         PSI contact discovery
│   │   ├── chat/             Encrypted message thread
│   │   └── settings/         Tor toggle, BT mesh, key backup
│   └── network/
│       ├── TorManager.kt     arti (Rust) Tor circuit management
│       ├── SolanaClient.kt   JSON-RPC for Arcium PSI
│       └── BluetoothMeshManager.kt  BLE offline relay
└── .github/workflows/android-ci.yml
```

## FFI Strategy

The Rust crate `crates/mobile-ffi` uses **UniFFI 0.28** with proc-macro bindings.
At build time, UniFFI generates `uniffi/arcium_core/arcium_core.kt`.
`ArciumCore.kt` wraps those generated bindings.

**Critical rule:** All cryptography (X3DH, Double Ratchet, RescueCipher, encrypted
storage) runs in Rust. Kotlin only calls through FFI — never reimplements crypto.

## How to Build Locally

1. Install Android Studio Iguana (2023.2.1) or later.
2. Open this repo's root in Android Studio → select `android/` as the project root.
3. Android Studio will sync Gradle and download SDK components automatically.
4. Before running: build the Rust FFI library:
   ```
   cd crates/mobile-ffi
   cargo build --target aarch64-linux-android --release
   ```
   Then copy `libarcium_core.so` into `android/app/src/main/jniLibs/arm64-v8a/`.
5. Run `app` configuration on a device or emulator (API 26+).

## TODO before first real run

- [ ] Wire `ArciumCore.kt` to generated UniFFI bindings
- [ ] Add `gradle-wrapper.jar` (`gradle wrapper --gradle-version 8.9`)
- [ ] Set up Android NDK + cargo-ndk for Rust cross-compilation
- [ ] Replace `lutOffset = new BN(0)` with real on-chain `mxeAccount.lutOffsetSlot`
- [ ] Implement TorManager Tor circuit bootstrap
- [ ] Implement SolanaClient JSON-RPC calls
- [ ] Implement BLE GATT mesh transport
