package com.arcium.messenger.ffi

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Kotlin wrapper for the Rust core library exposed via UniFFI.
 *
 * The Rust crate `mobile-ffi` (crates/mobile-ffi/src/lib.rs) uses:
 *   uniffi::setup_scaffolding!()
 *   #[uniffi::export] on Identity and ArciumCore structs
 *
 * UniFFI generates `uniffi/arcium_core/arcium_core.kt` at build time.
 * That generated file contains the real `Identity` and `ArciumCore` classes.
 *
 * At devnet deploy time, wire each method to the generated bindings:
 *   val core = uniffi.arcium_core.ArciumCore(storagePath, masterKey)
 *   val id   = uniffi.arcium_core.Identity.generate()
 */
@Singleton
class ArciumCoreWrapper @Inject constructor() {

    init {
        // TODO: load the compiled Rust .so at runtime
        // System.loadLibrary("arcium_core")
    }

    /** Generate a new Ed25519 + X25519 identity keypair via Rust. */
    fun generateIdentity(): ByteArray {
        // TODO: wire to uniffi.arcium_core.Identity.generate().publicKeyBytes()
        return ByteArray(32) // stub — 32-byte mock public key
    }

    /**
     * Perform X3DH key agreement to establish a session with a peer.
     * @param peerPublicKey 32-byte X25519 public key of the peer
     * @return 32-byte shared secret
     */
    fun x3dhInit(peerPublicKey: ByteArray): ByteArray {
        // TODO: wire to Rust X3DH implementation in core-crypto
        return ByteArray(32)
    }

    /**
     * Encrypt a message using the Double Ratchet protocol.
     * @param plaintext raw message bytes
     * @param sessionId identifies the ratchet session
     * @return ciphertext with ratchet header
     */
    fun ratchetEncrypt(plaintext: ByteArray, sessionId: String): ByteArray {
        // TODO: wire to Rust RatchetSession in core-crypto
        return plaintext // stub passthrough
    }

    /**
     * Decrypt a Double Ratchet ciphertext.
     * @param ciphertext encrypted message bytes (including ratchet header)
     * @param sessionId identifies the ratchet session
     * @return decrypted plaintext
     */
    fun ratchetDecrypt(ciphertext: ByteArray, sessionId: String): ByteArray {
        // TODO: wire to Rust RatchetSession in core-crypto
        return ciphertext // stub passthrough
    }

    /**
     * Submit a Private Set Intersection query to the Arcium MPC cluster.
     * Phone hashes are encrypted client-side with RescueCipher before sending.
     * @param phoneHashes list of u64 phone hash values (SHA256[0..8] LE)
     * @return bitmask of which hashes matched on the server side
     */
    fun submitPsiQuery(phoneHashes: List<Long>): BooleanArray {
        // TODO: wire to arcium-psi TS client or a Kotlin Solana RPC client
        return BooleanArray(phoneHashes.size) { false }
    }

    /**
     * Open the encrypted SQLite database (XChaCha20-Poly1305 via core-storage).
     * @param storagePath filesystem path to the database file
     * @param masterKey 32-byte key derived from user PIN or biometric
     */
    fun openEncryptedDb(storagePath: String, masterKey: ByteArray) {
        // TODO: wire to uniffi.arcium_core.ArciumCore(storagePath, masterKey)
    }
}
