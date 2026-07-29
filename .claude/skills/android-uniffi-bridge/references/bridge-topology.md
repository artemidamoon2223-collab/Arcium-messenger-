# Bridge topology

Derived from repository files. **Re-derive before relying on a detail here:**

```bash
cat .github/actions/uniffi-android-bridge/action.yml
cat .github/workflows/android-native-bridge.yml
sed -n '/\[lib\]/,/^$/p' crates/mobile-ffi/Cargo.toml
grep -n jna android/app/build.gradle.kts
```

## Pipeline

The composite action `.github/actions/uniffi-android-bridge` is the single
source of truth for building and generating the bridge. The workflow
`android-native-bridge.yml` (job `bridge-compile-package`) calls it, then asks
Gradle to compile and package.

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
5. **Cross build per ABI.** For each entry, `CC_*`, `CXX_*`, `AR_*`, `RANLIB_*`
   are exported for the NDK toolchain and
   `cargo build --locked -p mobile-ffi --release --target <rust_target>` runs.
   Each resulting `libarcium_core.so` is placed in its own
   `jniLibs/<abi>` directory.
6. **Gradle.** The workflow asserts the generated Kotlin file and both `.so`
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
`android/app/src/main/kotlin/com/arcium/messenger/ffi/ArciumCore.kt` still
carries a stale `// TODO: System.loadLibrary(...)` comment that should not be
acted on literally.

## Export-surface hazard

`#[uniffi::export]` applies to a whole `impl` block. Every method in that block
becomes callable Kotlin API regardless of Rust `pub`/private visibility.
Private helpers belong in a separate, non-exported `impl` block. Root cause of
finding X-2 in `docs/SECURITY-FINDINGS.md`; the fix was to split the block, and
fresh bindgen output confirmed the helper disappeared from the generated Kotlin
while the intended methods remained.

## The proof boundary

| Established by CI | Not established by CI |
|---|---|
| Rust cross-compiles for each ABI | `System.loadLibrary` succeeds on a device |
| UniFFI bindgen produces Kotlin that compiles | Any Kotlin↔Rust call executes |
| `.so` is packaged into the APK per ABI | Message encryption, ratchet, transport, PSI behaviour |
| Gradle assembles a debug APK | Persistence across process restart |
| | Production readiness |

Runtime confirmation requires installing on an emulator or device and
exercising the path by hand. Where a task needs that, say so and leave it to
the owner rather than implying the build covered it.

## Local build recipe — unverified

The previous `CLAUDE.md` documented a local cross-build using `cargo ndk`:

```bash
cargo build -p mobile-ffi                                   # generate .kt
cargo ndk -t arm64-v8a build -p mobile-ffi --release        # needs NDK
# → target/aarch64-linux-android/release/libarcium_core.so
```

This is **not** the mechanism CI uses — CI calls plain `cargo build --target`
with NDK clang environment variables exported, and does not use `cargo-ndk`.
The recipe is preserved because it may be the intended local workflow, but it
is unverified in this environment: `cargo-ndk` is not installed in the agent
sandbox and no CI job exercises it.
