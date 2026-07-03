package com.arcium.messenger.ffi

/**
 * Thin wrapper around the real UniFFI-generated bindings for the `mobile-ffi`
 * Rust crate (native library `arcium_core`).
 *
 * x86_64 Android development/emulator builds only — arm64-v8a is not built or
 * packaged by this bridge.
 *
 * This wrapper intentionally exposes only the FFI smoke boundary
 * (`checkBridge()`). Identity, ratchet, storage, and transport are not wired
 * into the Android app through this class yet.
 */
private object ArciumNativeLibrary {
    init {
        System.loadLibrary("arcium_core")
    }
}

class ArciumCoreWrapper {

    /**
     * Calls the real Rust `bridge_version()` export through the generated
     * UniFFI Kotlin bindings. Returns a fixed, non-secret marker string on
     * success; throws if the native call is unavailable or fails.
     */
    fun checkBridge(): String {
        ArciumNativeLibrary // touch the object to trigger System.loadLibrary once
        return uniffi.arcium_core.bridgeVersion()
    }
}
