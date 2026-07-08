package com.arcium.messenger.ffi

/**
 * Temporary manual Kotlin interface mocking future UniFFI-generated bindings.
 *
 * UniFFI will generate `uniffi/arcium_core/arcium_core.kt` from `mobile-ffi`.
 * Replace stubs with generated calls, e.g.:
 *   uniffi.arcium_core.Identity.generate().publicKeyBytes()
 *
 * CRITICAL: all crypto (X3DH, Double Ratchet, RescueCipher) and Tor (arti)
 * stay in Rust. Kotlin only calls through FFI — never reimplements crypto.
 */
class ArciumCoreWrapper {

    init {
        // TODO: System.loadLibrary("arcium_core") once .so is in jniLibs/
    }

    fun generateIdentity(): ByteArray {
        // Real FFI call through the generated UniFFI bindings. The native library
        // is loaded lazily by JNA on this first generated FFI call; any
        // UnsatisfiedLinkError propagates — there is no fallback to a stub.
        return uniffi.arcium_core.Identity.generate().publicKeyBytes()
    }

    fun x3dhInit(peerPublicKey: ByteArray): ByteArray {
        // TODO: wire to Rust X3DH in core-crypto
        return ByteArray(32)
    }

    fun ratchetEncrypt(plaintext: ByteArray, sessionId: String): ByteArray {
        // TODO: wire to Rust RatchetSession in core-crypto
        return plaintext
    }

    fun ratchetDecrypt(ciphertext: ByteArray, sessionId: String): ByteArray {
        // TODO: wire to Rust RatchetSession in core-crypto
        return ciphertext
    }

    fun submitPsiQuery(phoneHashes: List<Long>): BooleanArray {
        // TODO: RescueCipher + Arcium MPC PSI (NOT XChaCha20 — incompatible with MPC)
        return BooleanArray(phoneHashes.size) { false }
    }

    fun startTorTransport() {
        // TODO: wire to core-transport (Rust arti) via UniFFI — no Tor in Kotlin
    }

    fun openEncryptedDb(storagePath: String, masterKey: ByteArray) {
        // TODO: uniffi.arcium_core.ArciumCore(storagePath, masterKey)
    }
}
