# Arcium Messenger — Android

Kotlin + Jetpack Compose app for the anonymous E2E messenger.

## Structure

```
android/
├── app/src/main/kotlin/com/arcium/messenger/
│   ├── ArciumApp.kt          Application: opens the encrypted store at start-up
│   ├── MainActivity.kt       Compose + Navigation host
│   ├── ffi/
│   │   └── ArciumCore.kt     UniFFI wrapper around the Rust core library
│   ├── data/
│   │   ├── IdentityRepository.kt
│   │   └── MessageRepository.kt
│   ├── messaging/            Development relay settings, sync loop, contact cards
│   ├── security/             Master key, wrapped by an Android Keystore key
│   ├── startup/              Start-up checks of the master key and store
│   └── ui/
│       ├── theme/            Material 3 dark theme (Color, Type, Theme)
│       ├── navigation/       AppNavigation.kt — all routes
│       ├── startup/          Start-up error screen and retry
│       ├── onboarding/       Generate identity keys
│       ├── contacts/         Contact list; add a contact by pasting their card
│       ├── chat/             Encrypted message thread
│       └── settings/         Development relay address; what is not provided
└── e2e/                      Host scripts that drive the emulator end-to-end tests
```

The Android CI workflows are in the repository root, under
`.github/workflows/` (`android-*.yml`).

## FFI Strategy

The Rust crate `crates/mobile-ffi` uses **UniFFI 0.28** with proc-macro bindings.
Before Gradle runs, UniFFI generates `uniffi/arcium_core/arcium_core.kt` from it
(see "How to Build Locally"). `ArciumCore.kt` wraps those generated bindings.

**Critical rule:** All cryptography (X3DH, Double Ratchet, RescueCipher, encrypted
storage) runs in Rust. Kotlin only calls through FFI — never reimplements crypto.
The exception is the store's master key, which Kotlin generates and wraps with a
non-exportable AES-256-GCM key in the Android Keystore
(`security/MasterKeyProvider.kt`).

## How to Build Locally

1. Install an Android Studio release that supports Android Gradle Plugin 8.6.1
   (`gradle/libs.versions.toml`), with JDK 17.
2. Open this repo's root in Android Studio → select `android/` as the project root.
3. Android Studio will sync Gradle and download SDK components automatically.
4. Before building, generate the two inputs the app does not compile without,
   neither of which is committed: the UniFFI Kotlin bindings
   (`uniffi.arcium_core`, used by `ffi/ArciumCore.kt`) and the native library
   `libarcium_core.so`. In CI they come from the composite action
   `.github/actions/uniffi-android-bridge/action.yml`, which the Android
   workflows (`android-ci.yml`, `android-native-bridge.yml`,
   `android-build-baseline.yml`, `android-instrumentation.yml`,
   `android-two-device-e2e.yml`) run before Gradle. It:
   - builds `mobile-ffi` for the host and generates the Kotlin bindings from
     it with a `uniffi-bindgen` matching the `uniffi` version in `Cargo.lock`;
   - cross-compiles `libarcium_core.so` for `x86_64` and `arm64-v8a` with
     Android NDK 27.2.12479018;
   - writes both under `android/app/build/generated/rustBridge/` (`kotlin/`
     and `jniLibs/<abi>/`), which `app/build.gradle.kts` adds as source sets.

   There is no separate local script: a local build has to reproduce that
   action's steps, which are exercised only in CI.
5. Run `app` configuration on a device or emulator (API 26+). CI builds with
   `./gradlew testDebugUnitTest` and `./gradlew assembleDebug` in `android/`
   (`android-ci.yml`).

Only a debug build accepts a relay address: to exchange messages, run the
development relay (`arcium-relay` from `crates/relay`, see
`docs/NET-MESSAGING.md`) and enter its `host:port` in Settings.

## Not implemented yet

- Tor routing: `crates/core-transport` (arti) has no caller, and
  `ArciumCore.startTorTransport` throws (F-15).
- PSI contact discovery: `mobile-ffi` exports no PSI surface, and
  `ArciumCore.submitPsiQuery` throws. The PSI program is not deployed; the
  `lutOffset = new BN(0)` placeholder in `arcium-psi/tests/src/program.ts` must
  be replaced with the on-chain `mxeAccount.lutOffsetSlot` (`docs/HOME-DEPLOY.md`).
- Sync while the app is closed, Bluetooth mesh, key backup.
- A production relay and release signing.
