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
│   ├── messaging/            Relay settings, sync loop, background receive, contact cards
│   ├── security/             Master key, wrapped by an Android Keystore key
│   ├── startup/              Start-up checks of the master key and store
│   └── ui/
│       ├── theme/            Material 3 dark theme (Color, Type, Theme)
│       ├── navigation/       AppNavigation.kt — all routes
│       ├── startup/          Start-up error screen and retry
│       ├── onboarding/       Generate identity keys
│       ├── contacts/         Contact list; add a contact by pasting their card
│       ├── chat/             Encrypted message thread
│       └── settings/         Relay connection string; what is not provided
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

## Configuring a relay

Messaging stays off until a relay is entered in Settings; there is no
default. Rules: `messaging/RelayRules.kt` (unit tests in
`src/test/.../messaging/RelayRulesTest.kt`), applied by
`messaging/RelaySettings.kt`.

- **Every build** accepts a `RELAY_PROTOCOL_V2` connection string,
  `arcium-relay-v2:<host>:<port>:<tls_pin>:<auth_pk>`, which the relay's
  operator gets from `arcium-relay keygen` (`docs/NET-MESSAGING.md`,
  section 3). The app then reaches the relay over TLS 1.3, accepts only the
  pinned key, and authenticates as this device's identity key before it
  reads, deletes or publishes; only this device can read or delete its
  mailbox (the relay's operator still can). Settings shows "Encrypted relay
  (V2)".
- **Debug builds only** (`DEV_RELAY_ALLOWED` in `app/build.gradle.kts`) also
  accept `host:port` of a development relay (`arcium-relay` without
  `--keys`): no TLS and no authentication, so anyone on the network sees
  what the relay sees and anyone who reaches it can read or delete any
  mailbox. Settings shows "Development relay (V1)". A release build refuses
  it, and ignores one stored by an earlier build.
- A string that starts with `arcium-relay-v2:` but is malformed is refused,
  never read as `host:port`. The Rust core parses the string again on every
  connection; a wrong pin, a refused authentication or an address the core
  refuses shows as the relay being unreachable.
- No QR code yet: the string is pasted.

The emulator workflows in CI run debug builds against a development (V1)
relay.

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
- It runs only once start-up is Ready, with a relay configured and with the
  app's notifications allowed, and it stops
  itself when the switch is turned off or the relay is removed
  (`backgroundState` in `messaging/BackgroundRules.kt`). The open app starts
  it; Settings says why it is not running.
- While it runs, a low-importance notification says that the app stays
  connected to the relay in the background. When a round records a text from
  a contact while the app is not visible, a notification says "New message":
  no sender and no text, and neither notification is shown on the lock screen
  (`VISIBILITY_SECRET`); tapping it opens the app. A new text is found from
  each conversation's newest entry (`notifyAfterRound`), not from the unread
  count. A chat screen marks texts seen only while the app is visible, so
  texts that arrive in the background stay unread until the user returns.
- It checks again every 30 s that the app's notifications are still allowed
  (below Android 13, turning them off does not end the process), and stops
  if not.
- Pace: while only the service runs the loop, a round that changed nothing
  is followed by a 30 s wait (`BACKGROUND_IDLE_DELAY_MS` in
  `messaging/BackgroundRules.kt`), against 4 s while the app is on screen. A
  round that received something is followed by the fast pace, so replies
  and receipts follow quickly. Each round is a new connection that publishes
  the bundle and scans the mailbox: a slower pace also means the device shows
  itself to the relay and the network less often.

What it does not do:

- Start after a reboot (there is no `BOOT_COMPLETED` receiver), or start
  again after Android ends the app's process (`START_NOT_STICKY`: a start
  request already sent is still delivered, but nothing new is started).
  Nothing is received then until the app is opened.
- Keep the device awake: it holds no wake lock, so while the device sleeps
  rounds can pause and texts can arrive late. Not measured.
- Cost nothing: about 120 idle rounds an hour while the device is awake.
  Battery and data cost have not been measured on a phone.
- Run without limit on Android 15 targets: the app targets SDK 34 today. A
  target of 35 or later limits `dataSync` services to 6 hours a day and
  needs `onTimeout` handled; that is not done.
- Use the Keystore: the store is opened once per process, at start-up
  (`ArciumApp.onCreate`), and the service is started only from the open app
  and never restarted. Requiring an unlocked device or user authentication
  for the wrapping key (R-18 (b) in `docs/SECURITY-FINDINGS.md`) would bear
  on starting the process without the user (after a reboot, or after the
  process was ended), which this service does not do, rather than on a
  running service. While it runs, the store stays open, with its key in the
  process's memory, also while the device is locked.

## Not implemented yet

- Tor routing: `crates/core-transport` (arti) has no caller, and
  `ArciumCore.startTorTransport` throws (F-15).
- PSI contact discovery: `mobile-ffi` exports no PSI surface, and
  `ArciumCore.submitPsiQuery` throws. The PSI program is not deployed; the
  `lutOffset = new BN(0)` placeholder in `arcium-psi/tests/src/program.ts` must
  be replaced with the on-chain `mxeAccount.lutOffsetSlot` (`docs/HOME-DEPLOY.md`).
- Push notifications, Bluetooth mesh, key backup.
- A deployed production relay (the app can be configured with one; none
  is run by this project yet) and release signing.
