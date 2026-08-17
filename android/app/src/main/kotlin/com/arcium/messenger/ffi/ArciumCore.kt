package com.arcium.messenger.ffi

/**
 * Kotlin wrapper over the UniFFI-generated bindings (`uniffi.arcium_core`,
 * generated at build time from `mobile-ffi`).
 *
 * Identity generation and persistence are real FFI calls. The remaining
 * methods (X3DH, ratchet, PSI, Tor) are not wired to Rust yet and throw
 * NotImplementedError; none of them returns a value that could be mistaken
 * for a real result.
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

    /**
     * Not connected yet. The Rust side exposes `establishSessionInitiator` and
     * `establishSessionResponder` on `uniffi.arcium_core.ArciumCore`; this
     * wrapper method is not wired to either. Throws rather than returning a
     * 32-byte zero array, which a caller could not tell from a real handshake.
     */
    fun x3dhInit(peerPublicKey: ByteArray): ByteArray {
        throw NotImplementedError(
            "x3dhInit is not wired to Rust: X3DH lives in core-crypto and is reached through " +
                "ArciumCore.establishSessionInitiator/establishSessionResponder over UniFFI. " +
                "No Kotlin-side handshake exists.",
        )
    }

    /**
     * Not connected yet. The Rust side exposes `encryptMessage(sessionId, plaintext)`;
     * this wrapper method is not wired to it. Throws rather than echoing the
     * plaintext back, which would look like ciphertext to every caller.
     */
    fun ratchetEncrypt(plaintext: ByteArray, sessionId: String): ByteArray {
        throw NotImplementedError(
            "ratchetEncrypt is not wired to Rust: the Double Ratchet lives in core-crypto and is " +
                "reached through ArciumCore.encryptMessage over UniFFI. Nothing here encrypts.",
        )
    }

    /**
     * Not connected yet. The Rust side exposes `decryptMessage(sessionId, message)`;
     * this wrapper method is not wired to it. Throws rather than echoing the
     * ciphertext back as if it had been decrypted.
     */
    fun ratchetDecrypt(ciphertext: ByteArray, sessionId: String): ByteArray {
        throw NotImplementedError(
            "ratchetDecrypt is not wired to Rust: the Double Ratchet lives in core-crypto and is " +
                "reached through ArciumCore.decryptMessage over UniFFI. Nothing here decrypts.",
        )
    }

    /**
     * Not connected yet, and no UniFFI export exists for it: PSI stays
     * RescueCipher + Arcium MPC in Rust. Throws rather than returning an
     * all-false result, which is indistinguishable from "no contacts matched".
     */
    fun submitPsiQuery(phoneHashes: List<Long>): BooleanArray {
        throw NotImplementedError(
            "submitPsiQuery is not wired to Rust: private contact discovery is RescueCipher + " +
                "Arcium MPC on the Rust/on-chain side (never XChaCha20 — incompatible with MPC), " +
                "and mobile-ffi exports no PSI surface yet. An all-false answer would be a lie.",
        )
    }

    /**
     * Not connected yet, and no UniFFI export exists for it: transport stays
     * arti in Rust. Throws rather than returning silently, which would read as
     * "Tor is up".
     */
    fun startTorTransport() {
        throw NotImplementedError(
            "startTorTransport is not wired to Rust: the Tor onion transport is arti in " +
                "core-transport, and mobile-ffi exports no transport surface yet. Returning " +
                "quietly would imply Tor was running.",
        )
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
