---
name: android-uniffi-bridge
description: "How the Rust↔Kotlin UniFFI bridge is generated, cross-compiled, packaged and run on Android, and what a successful build or Android test run does and does not prove. Use when changing the FFI surface of crates/mobile-ffi (#[uniffi::export] items, exported records and errors, uniffi.toml), the generated Kotlin bindings, the JNA dependency, jniLibs packaging, or the Android workflows that build or run the bridge — and whenever stating what an Android build or test run proved. Does not authorize dependency updates or bridge-code fixes."
---

# android-uniffi-bridge

## Status

Describes the CI topology as last checked at `main` `483a664` (2026-10-31).
Re-read the referenced files before relying on any detail — see
`references/bridge-topology.md` for the re-derivation commands.

Authorizes nothing. Updating dependencies, changing the bridge code, or
touching Gradle configuration each require their own explicit instruction.

## Purpose

The bridge's evidence comes in levels, and the levels are easy to state
wrongly:

- `android-native-bridge.yml`, `android-ci.yml` and the dispatch-only
  `android-build-baseline.yml` prove **compile and packaging** only
  (`android-ci.yml` also runs JVM unit tests on the build host, not on Android).
- `android-instrumentation.yml` and `android-two-device-e2e.yml` **execute**
  Kotlin↔Rust calls — but only on x86_64 Android 11 (API 30) emulators, and
  only for what their tests assert. The arm64-v8a library is built and
  packaged, never run in CI; no physical device runs anything in CI.

Keeping these levels explicit is most of what this skill is for.

## Use when

- Changing `crates/mobile-ffi` — especially anything inside a
  `#[uniffi::export]` block.
- Working on the generated Kotlin bindings or code that calls them.
- Touching the JNA dependency, `jniLibs` packaging, or
  `android/app/build.gradle.kts`.
- Changing `.github/actions/uniffi-android-bridge/action.yml` or a workflow
  that uses it (`grep -l uniffi-android-bridge .github/workflows/*.yml`).
- Writing a claim about what an Android build or test run proved.

## Do not use when

- The change is confined to `arcium-psi/` — that is a separate cargo workspace
  and does not affect the bridge.
- The task is a plain Rust change with no FFI surface — including a change
  to `mobile-ffi`'s messaging or network logic that adds or alters no exported
  item.

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

5. **Check what CI actually ran.** Each Android workflow has its own path
   filter, and none fires on a docs-only diff or an `arcium-psi/` change. The
   list is in `engineering-code-review/references/delivery-checklist.md`
   («Which CI checks a diff actually triggers»); re-read the `on:` blocks at
   your SHA.

6. **State the claim at the right level** — see the boundary below.

## Constraints

- A successful `assembleDebug`, and a `.so` present in the APK for both ABIs,
  prove **compile and packaging topology only**. They do **not** prove that
  the library loads, that any Kotlin↔Rust call executes, that message
  encryption works, or that anything is production-ready.
- Never describe an APK build as evidence of runtime behaviour. Runtime
  evidence comes only from a test that ran: a green instrumentation or
  two-device run is `RUNTIME_VERIFIED` on an x86_64 API-30 emulator for exactly
  what its tests assert — not for arm64 phones, other API levels, background
  execution or production readiness. A physical-device run is manual and
  outside CI.
- Do not update the JNA version, the NDK version, the uniffi version, or the
  ABI list as a side effect of another task.
- Do not "fix" bridge code noticed in passing — report it instead.
- Do not commit generated bindings or `.so` files; they are build-directory
  output.

## References

- `references/bridge-topology.md` — the full pipeline, exact paths, pinned
  versions, and the commands to re-derive all of it.
