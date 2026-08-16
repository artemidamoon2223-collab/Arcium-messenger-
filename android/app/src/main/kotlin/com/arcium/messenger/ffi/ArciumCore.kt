package com.arcium.messenger.ffi

/**
 * Kotlin wrapper over the UniFFI-generated bindings (`uniffi.arcium_core`,
 * generated at build time from `mobile-ffi`).
 *
 * Identity generation and persistence are real FFI calls; the remaining
 * methods (X3DH, ratchet, PSI, Tor) are still hardcoded stubs awaiting
 * Rust-side UniFFI surface.
 *
 * CRITICAL: all crypto (X3DH, Double Ratchet, RescueCipher) and Tor (arti)
 * stay in Rust. Kotlin only calls through FFI — never reimplements crypto.
 */
class ArciumCoreWrapper {

    // Held handle to the Rust ArciumCore (encrypted store). Set by
    // openEncryptedDb(); the identity persistence methods require it.
    private var core: uniffi.arcium_core.ArciumCore? = null

    val isDbOpen: Boolean
        get() = core != null

    fun generateIdentity(): ByteArray {
        // Real FFI call through the generated UniFFI bindings. The native library
        // is loaded lazily by JNA on this first generated FFI call; any
        // UnsatisfiedLinkError propagates — there is no fallback to a stub.
        return uniffi.arcium_core.Identity.generate().publicKeyBytes()
    }

    /**
     * Generates a fresh identity, persists it into the open encrypted store,
     * then returns the 32-byte Ed25519 public key. The private key material
     * never crosses into Kotlin — it goes Rust Identity → Rust store directly.
     * Throws IllegalStateException if the DB is not open, CoreException on
     * storage failure. No fallback, no silent success.
     */
    fun generateAndSaveIdentity(): ByteArray {
        val c = core ?: error("encrypted DB is not open — call openEncryptedDb() first")
        uniffi.arcium_core.Identity.generate().use { identity ->
            c.saveIdentity(identity)
            return identity.publicKeyBytes()
        }
    }

    /**
     * Loads the persisted identity's public key. Returns null only when no
     * identity is stored (or the store cannot decrypt one — same semantics
     * as Rust load_identity). Throws IllegalStateException if the DB is not
     * open.
     */
    fun loadIdentityPublicKey(): ByteArray? {
        val c = core ?: error("encrypted DB is not open — call openEncryptedDb() first")
        return c.loadIdentity()?.use { it.publicKeyBytes() }
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

    /**
     * Opens (creating if absent) the encrypted store at [storagePath] with the
     * 32-byte [masterKey] and holds the handle for the identity methods above.
     * CoreException (InvalidKey/Storage) propagates — no silent catch, no
     * fake success. Reopening replaces (and disposes) the previous handle.
     */
    fun openEncryptedDb(storagePath: String, masterKey: ByteArray) {
        val previous = core
        core = uniffi.arcium_core.ArciumCore(storagePath, masterKey)
        previous?.close()
    }
}
