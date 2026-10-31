# Bridge topology

Derived from repository files. **Re-derive before relying on a detail here:**

```bash
cat .github/actions/uniffi-android-bridge/action.yml
cat crates/mobile-ffi/uniffi.toml
cat .github/workflows/android-native-bridge.yml
grep -n "arch:\|SYSTEM_IMAGE\|connectedDebugAndroidTest\|notPackage\|two_devices.py" \
  .github/workflows/android-instrumentation.yml .github/workflows/android-two-device-e2e.yml
sed -n '/\[lib\]/,/^$/p' crates/mobile-ffi/Cargo.toml
grep -n jna android/app/build.gradle.kts
```

## Pipeline

The composite action `.github/actions/uniffi-android-bridge` is the single
source of truth for building and generating the bridge. Five workflows call it
(`grep -l uniffi-android-bridge .github/workflows/*.yml`).
`android-native-bridge.yml` (job `bridge-compile-package`), `android-ci.yml` and
the dispatch-only `android-build-baseline.yml` then compile and package.
`android-instrumentation.yml` (job `connected-tests`) and
`android-two-device-e2e.yml` (job `two-devices`) also build the test APK and run
it on x86_64 API-30 emulators — see the proof boundary below.

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
6. **Cross build per ABI.** For each entry, `CC_*`, `CXX_*`, `AR_*`, `RANLIB_*`
   are exported for the NDK toolchain and
   `cargo build --locked -p mobile-ffi --release --target <rust_target>` runs.
   Each resulting `libarcium_core.so` is placed in its own
   `jniLibs/<abi>` directory.
7. **Gradle.** The workflow asserts the generated Kotlin file and both `.so`
   files exist *before* invoking Gradle, then runs
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
FFI call. A manual `System.loadLibrary("arcium_core")` is therefore redundant.

## Export-surface hazard

`#[uniffi::export]` applies to a whole `impl` block. Every method in that block
becomes callable Kotlin API regardless of Rust `pub`/private visibility.
Private helpers belong in a separate, non-exported `impl` block. Root cause of
finding X-2 in `docs/SECURITY-FINDINGS.md`; the fix was to split the block, and
fresh bindgen output confirmed the helper disappeared from the generated Kotlin
while the intended methods remained.

## The proof boundary

| Established by `android-native-bridge.yml` | Established on an x86_64 API-30 emulator by `android-instrumentation.yml` and `android-two-device-e2e.yml`, for what their tests assert | Not established by CI |
|---|---|---|
| Rust cross-compiles for each ABI | The packaged `libarcium_core.so` loads through JNA | Anything on arm64-v8a (built and packaged, never run) |
| UniFFI bindgen produces Kotlin that compiles | Kotlin↔Rust calls execute | Physical devices, other API levels, background or Doze behaviour |
| `.so` is packaged into the APK per ABI | Durable messaging across process death (instrumentation) and two app instances messaging through the development relay (two-device) | Tor, PSI, a production relay |
| Gradle assembles a debug APK | | Cryptographic correctness beyond what the tests assert; production readiness |

`android-instrumentation.yml` excludes the `com.arcium.messenger.e2e` package;
`android-two-device-e2e.yml` runs that package through `android/e2e/two_devices.py`.

Physical-device confirmation requires installing on a phone and exercising the
path by hand. Where a task needs that, say so and leave it to the owner rather
than implying that an emulator run or a build covered it.

## Local build recipe — unverified

The previous `CLAUDE.md` documented a local cross-build using `cargo ndk`:

```bash
cargo build -p mobile-ffi                                   # builds the crate; generates no .kt (build.rs only sets rerun-if-changed)
cargo ndk -t arm64-v8a build -p mobile-ffi --release        # needs NDK
# → target/aarch64-linux-android/release/libarcium_core.so
```

This is **not** the mechanism CI uses — CI calls plain `cargo build --target`
with NDK clang environment variables exported, and does not use `cargo-ndk`.
The recipe is preserved because it may be the intended local workflow, but it
is unverified in this environment: `cargo-ndk` is not installed in the agent
sandbox and no CI job exercises it.
