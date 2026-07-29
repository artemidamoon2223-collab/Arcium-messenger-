---
name: android-uniffi-bridge
description: "How the Rust↔Kotlin UniFFI bridge is generated, cross-compiled, and packaged for Android, and what a successful build does and does not prove. Use when touching crates/mobile-ffi, the generated Kotlin bindings, the JNA dependency, jniLibs packaging, or the android-native-bridge workflow. Does not authorize dependency updates or bridge-code fixes."
---

# android-uniffi-bridge

## Status

Describes existing, working CI topology as of the commit this file was written
against. Re-read the referenced files before relying on any detail — see
`references/bridge-topology.md` for the re-derivation commands.

Authorizes nothing. Updating dependencies, changing the bridge code, or
touching Gradle configuration each require their own explicit instruction.

## Purpose

The bridge has one property that is easy to state wrongly: **it is verified at
compile-and-package level only.** No CI job in this repository has ever
executed a Kotlin↔Rust call. Keeping that boundary explicit is most of what
this skill is for.

## Use when

- Changing `crates/mobile-ffi` — especially anything inside a
  `#[uniffi::export]` block.
- Working on the generated Kotlin bindings or code that calls them.
- Touching the JNA dependency, `jniLibs` packaging, or
  `android/app/build.gradle.kts`.
- Changing `.github/workflows/android-native-bridge.yml` or
  `.github/actions/uniffi-android-bridge/action.yml`.
- Writing a claim about what an Android build proved.

## Do not use when

- The change is confined to `arcium-psi/` — that is a separate cargo workspace
  and does not affect the bridge.
- The task is a plain Rust change with no FFI surface.

## Workflow

1. **Know which manifest you are in.** `crates/mobile-ffi` belongs to the
   repository-root workspace. `arcium-psi/` is a *different* workspace. Profile
   settings for one do not reach the other.

2. **Regenerate bindings from Rust, do not hand-edit them.** The Kotlin
   bindings under `android/app/build/generated/rustBridge/kotlin/` are build
   output. Editing them is always wrong; change the Rust and regenerate.

3. **Watch the export surface.** `#[uniffi::export]` applies to an entire
   `impl` block — every method in it is exported regardless of Rust visibility.
   Private helpers must live in a separate, non-exported `impl` block. This is
   how a private `require_identity()` once became callable Kotlin API (X-2 in
   `docs/SECURITY-FINDINGS.md`).

4. **Let JNA load the library.** Do not add a manual
   `System.loadLibrary("arcium_core")` call. The generated bindings load the
   native library lazily through JNA on first FFI call.

5. **Check what CI actually ran.** `bridge-compile-package` fires on
   `crates/**`, the root `Cargo.toml`, `android/app/build.gradle.kts`, and its
   own workflow file — not on docs-only diffs, and not on `arcium-psi/` changes.

6. **State the claim at the right level** — see the boundary below.

## Constraints

- A successful `assembleDebug`, and a `.so` present in the APK for both ABIs,
  prove **compile and packaging topology only**. They do **not** prove that
  `System.loadLibrary` succeeds on a device, that any Kotlin↔Rust call
  executes, that message encryption works, or that anything is production-ready.
- Never describe an APK build as evidence of runtime behaviour. Runtime proof
  requires an emulator or device, and is a separate, manual step.
- Do not update the JNA version, the NDK version, the uniffi version, or the
  ABI list as a side effect of another task.
- Do not "fix" bridge code noticed in passing — report it instead.
- Do not commit generated bindings or `.so` files; they are build-directory
  output.

## References

- `references/bridge-topology.md` — the full pipeline, exact paths, pinned
  versions, and the commands to re-derive all of it.
