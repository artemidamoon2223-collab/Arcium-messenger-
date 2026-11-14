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
│   ├── messaging/            Development relay settings, sync loop, background receive, contact cards
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

## Background receive

Off by default. Turning on "Receive in the background" in Settings starts
`messaging/BackgroundReceiveService.kt`, a foreground service of type
`dataSync` (permissions `FOREGROUND_SERVICE` and
`FOREGROUND_SERVICE_DATA_SYNC`; on Android 13 and later the switch first asks
for `POST_NOTIFICATIONS`). There is no push service, no Google FCM and no
server of its own: the service runs the app's sync loop
(`MessengerService.syncInBackground`) against the same relay.

- One loop at a time. The open app and the service share the loop behind a
  lock (`MessengerService.syncLoop`), and every round still runs on the one
  sync thread.
- It runs only once start-up is Ready, with a relay configured (so only in
  debug builds today) and with the app's notifications allowed, and it stops
  itself when the switch is turned off or the relay is removed
  (`backgroundState` in `messaging/BackgroundRules.kt`). The open app starts
  it; Settings says why it is not running.
- While it runs, a low-importance notification says that the app stays
  connected to the relay in the background. When a round records a text from
  a contact while the app is not visible, a notification says "New message":
  no sender and no text, private on the lock screen; tapping it opens the
  app. A new text is found from each conversation's newest entry
  (`notifyAfterRound`), not from the unread count, which an open chat screen
  clears as texts arrive.

What it does not do:

- Start after a reboot (there is no `BOOT_COMPLETED` receiver), or start
  again after Android ends the app's process (`START_NOT_STICKY`). Nothing is
  received then until the app is opened.
- Keep the device awake: it holds no wake lock, so while the device sleeps
  rounds can pause and texts can arrive late. Not measured.
- Save battery or data: it keeps the open app's pace, a round about every
  4 s while nothing arrives (`IDLE_DELAY_MS` in `MessengerService.kt`). The
  cost has not been measured.
- Use the Keystore: the store is opened once per process, at start-up
  (`ArciumApp.onCreate`), and the service is started only from the open app
  and never restarted. Requiring an unlocked device or user authentication
  for the wrapping key (R-18 (b) in `docs/SECURITY-FINDINGS.md`) would bear
  on starting the process without the user (after a reboot, or after the
  process was ended), which this service does not do, rather than on a
  running service.

## Not implemented yet

- Tor routing: `crates/core-transport` (arti) has no caller, and
  `ArciumCore.startTorTransport` throws (F-15).
- PSI contact discovery: `mobile-ffi` exports no PSI surface, and
  `ArciumCore.submitPsiQuery` throws. The PSI program is not deployed; the
  `lutOffset = new BN(0)` placeholder in `arcium-psi/tests/src/program.ts` must
  be replaced with the on-chain `mxeAccount.lutOffsetSlot` (`docs/HOME-DEPLOY.md`).
- Push notifications, Bluetooth mesh, key backup.
- A production relay and release signing.
