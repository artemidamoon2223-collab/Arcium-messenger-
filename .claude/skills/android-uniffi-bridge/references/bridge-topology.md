# Bridge topology

Derived from repository files. **Re-derive before relying on a detail here:**

```bash
cat .github/actions/uniffi-android-bridge/action.yml
cat crates/mobile-ffi/uniffi.toml
grep -rn "uniffi-android-bridge" .github/workflows   # every caller of the action
cat .github/workflows/android-native-bridge.yml
grep -n "arch:\|api-level\|SYSTEM_IMAGE" .github/workflows/android-*.yml  # what the emulators run
sed -n '/\[lib\]/,/^$/p' crates/mobile-ffi/Cargo.toml
grep -n jna android/app/build.gradle.kts
grep -rn "loadLibrary" android/                      # empty = JNA loads the library
```

## Pipeline

The composite action `.github/actions/uniffi-android-bridge` is the single
source of truth for building and generating the bridge. At `de328a1` it is
called by every Android workflow that builds the app (re-derive with the grep
above):

- `android-ci.yml` (job `build`) — JVM unit tests, debug APK, and the
  instrumentation APK, compiled but not run;
- `android-native-bridge.yml` (job `bridge-compile-package`) — debug APK, then
  checks the `.so` is packaged for every ABI (step 7 below);
- `android-instrumentation.yml` (job `connected-tests`) — runs `src/androidTest`
  on one x86_64 API-30 emulator, against a relay and a peer on the host;
- `android-two-device-e2e.yml` (job `two-devices`) — the two-device scenario on
  two x86_64 API-30 emulators;
- `android-build-baseline.yml` (job `android-build`) — manual
  (`workflow_dispatch`) debug APK build.

1. **ABI list.** `ABI_TARGETS` inside the composite action is the single source
   of truth for which Android ABIs are built. Each entry carries a Rust target,
   an Android ABI name, and an NDK clang triple.
2. **Toolchain.** The NDK version is pinned in the action (`NDK_VERSION`), and
   each Rust target is added via `rustup target add`.
3. **Ephemeral bindgen.** A throwaway `uniffi-bindgen` helper crate is
   generated and `cargo install`ed, pinned to the same `uniffi` version the
   workspace locks. This avoids a bindgen/runtime version skew.
4. **Host build for metadata.** `mobile-ffi` is first built for the host with
   `--config 'profile.release.strip=false'`, because the bindgen step reads
   UniFFI metadata out of the unstripped host library.
5. **Generated-Kotlin plaintext check.** Bindgen reads
   `crates/mobile-ffi/uniffi.toml`, which maps the custom types
   `PlaintextBytes`/`PlaintextText` (`crates/mobile-ffi/src/plaintext.rs`) to
   the Kotlin value classes in
   `android/app/src/main/kotlin/com/arcium/messenger/ffi/Plaintext.kt`, whose
   `toString` is `"<redacted>"`. The action then runs
   `check_generated_plaintext.py --self-test` on the generated file: every
   generated property whose type is or contains `kotlin.String`,
   `kotlin.ByteArray` or a `Plaintext*` type must match
   `generated-string-fields.txt` exactly, or the action fails. A new record
   field of those types therefore needs a line there, and message plaintext
   needs one of the custom types. The generated file is checked, never edited.
6. **Cross build per ABI.** For each entry, `CARGO_TARGET_*_LINKER`, `CC_*`,
   `CXX_*`, `AR_*`, `RANLIB_*` are exported for the NDK toolchain and
   `cargo build --locked -p mobile-ffi --release --target <rust_target>` runs.
   Each resulting `libarcium_core.so` is placed in its own
   `jniLibs/<abi>` directory.
7. **Gradle (`android-native-bridge.yml`).** The workflow asserts the
   generated Kotlin file and both `.so` files exist *before* invoking Gradle,
   then runs
   `./gradlew :app:assembleDebug`, then unzips the APK and checks
   `lib/<abi>/libarcium_core.so` is present for every ABI. A missing library
   exits non-zero.

## Generated output paths

Everything the bridge generates lands under the Gradle build directory and is
never committed:

```
android/app/build/generated/rustBridge/kotlin/uniffi/arcium_core/arcium_core.kt
android/app/build/generated/rustBridge/jniLibs/<abi>/libarcium_core.so
```

## Why the library is called `libarcium_core.so`

`crates/mobile-ffi/Cargo.toml` sets `[lib] name = "arcium_core"` with
`crate-type = ["cdylib", "staticlib"]`. The crate is named `mobile-ffi`, the
library is not — do not assume they match.

## JNA

`android/app/build.gradle.kts` pins `net.java.dev.jna:jna:<version>@aar`, with
a comment recording that the coordinate and minimum version come from the
UniFFI Kotlin documentation for the uniffi version in use.

The generated bindings load the native library lazily through JNA on the first
FFI call. A manual `System.loadLibrary("arcium_core")` is therefore redundant;
nothing under `android/` calls `loadLibrary`.

## Export-surface hazard

`#[uniffi::export]` applies to a whole `impl` block. Every method in that block
becomes callable Kotlin API regardless of Rust `pub`/private visibility.
Private helpers belong in a separate, non-exported `impl` block. Root cause of
finding X-2 in `docs/SECURITY-FINDINGS.md`; the fix was to split the block, and
fresh bindgen output confirmed the helper disappeared from the generated Kotlin
while the intended methods remained.

## The proof boundary

| level | x86_64 | arm64-v8a |
|---|---|---|
| Rust cross-compiles, bindgen output compiles, `.so` packaged into the debug APK | CI (`android-native-bridge.yml`) | CI (`android-native-bridge.yml`) |
| library loads through JNA and Kotlin↔Rust calls execute | CI, on API-30 emulators (`android-instrumentation.yml`, `android-two-device-e2e.yml`) | never executed |
| physical device | NOT_VERIFIED | NOT_VERIFIED |
| release build (`assembleRelease`) | NOT_VERIFIED: no workflow builds one | NOT_VERIFIED |

Emulator runtime evidence is a statement about a specific run: cite that run's
log (the test names and result lines it prints), not the workflow file. A workflow that exists is not a run that passed. What the emulator runs
cover is what the instrumentation tests exercise; each workflow's header says
what it does not cover (an emulator is not a phone: storage, power loss,
networks, delivery while the app is closed). For arm64-v8a, a physical device
or a release build, a task that needs runtime proof must say so and leave it to
the owner.

## Local builds

No script or workflow in this repository uses `cargo-ndk`; CI builds only
through the composite action (plain `cargo build --target` with the NDK clang
variables exported). `docs/HOME-DEPLOY.md` (step 7) still shows a `cargo ndk`
command that nothing runs, and names its output `libmobile_ffi.so`; the
library is `libarcium_core.so` (above). Do not treat either as a verified
recipe.
