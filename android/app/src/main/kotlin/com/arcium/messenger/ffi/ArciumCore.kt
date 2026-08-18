package com.arcium.messenger.ffi

/**
 * Kotlin wrapper over the UniFFI-generated bindings (`uniffi.arcium_core`,
 * generated at build time from `mobile-ffi`).
 *
 * Identity persistence and the messaging surface (X3DH handshake + Double
 * Ratchet) are real FFI calls. PSI and Tor have no UniFFI export yet and
 * throw NotImplementedError; none of them returns a value that could be
 * mistaken for a real result.
 *
 * This class is a pass-through and nothing more: it holds the open store
 * handle, checks it, and forwards. It derives no identifiers, catches no
 * CoreException, and decides nothing about which session a message belongs
 * to — session-identifier policy and inbound routing live above this layer
 * and are not wired yet.
 *
 * CRITICAL: all crypto (X3DH, Double Ratchet, RescueCipher) and Tor (arti)
 * stay in Rust. Kotlin only calls through FFI — never reimplements crypto.
 */
class ArciumCoreWrapper {

    // Held handle to the Rust ArciumCore (encrypted store). Set by
    // openEncryptedDb(); the identity and messaging methods require it.
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

    // ── Messaging: X3DH handshake + Double Ratchet ───────────────────────────
    //
    // Each method below forwards straight to the generated bindings. The typed
    // CoreException (Storage / InvalidKey / Handshake / NoSession /
    // SessionAlreadyExists / SessionIdCollision / Crypto) propagates unchanged:
    // it is never caught, never flattened into a Boolean or null, never
    // rewritten into a generic Exception.
    //
    // `sessionId` is a local lookup handle into the Rust SessionManager, not a
    // protocol field — it is absent from the prekey bundle, the handshake, the
    // message header, and the associated data. PR #75 established by test that
    // two peers may use different ids for the same cryptographic session, so
    // this wrapper neither derives nor validates ids; it passes through
    // whatever the caller chose.

    /**
     * Generates and persists this device's signed prekey plus a one-time
     * prekey, signed with the saved identity, so peers can open sessions
     * against this device. Calling it again overwrites the previous prekeys —
     * the Rust side has no "already established" guard. CoreException
     * propagates when no identity is saved or the store write fails.
     */
    fun establishPrekeys() {
        requireCore().establishPrekeys()
    }

    /**
     * Reads the already-persisted prekey bundle. A pure read: it generates
     * nothing and fails with CoreException if [establishPrekeys] never ran.
     * These are the bytes the peer feeds to [establishSessionInitiator] on
     * its own device.
     */
    fun exportPrekeyBundle(): ByteArray {
        return requireCore().exportPrekeyBundle()
    }

    /**
     * Opens a session as the X3DH initiator ("Alice") against [peerBundle] —
     * the peer's [exportPrekeyBundle] output — and registers it in Rust under
     * the local handle [sessionId]. An occupied handle is refused, never
     * overwritten: CoreException.SessionAlreadyExists for the same peer,
     * CoreException.SessionIdCollision for a different one.
     *
     * Returns the bytes the peer needs to finish the handshake through
     * [establishSessionResponder]. Delivering them is a transport concern and
     * is not wired here.
     */
    fun establishSessionInitiator(sessionId: ULong, peerBundle: ByteArray): ByteArray {
        return requireCore().establishSessionInitiator(sessionId, peerBundle)
    }

    /**
     * Opens a session as the X3DH responder ("Bob") from the initiator's
     * identity and ephemeral public keys — the two halves of the byte string
     * [establishSessionInitiator] returned on the other device — registering
     * it under the local handle [sessionId].
     *
     * Requires [establishPrekeys] to have run here first; CoreException
     * propagates otherwise. An occupied handle is refused here too. Initiator
     * and responder are separate, non-interchangeable roles — neither call
     * substitutes for the other.
     */
    fun establishSessionResponder(
        sessionId: ULong,
        aliceIdentityPk: ByteArray,
        aliceEphemeralPk: ByteArray,
    ) {
        requireCore().establishSessionResponder(sessionId, aliceIdentityPk, aliceEphemeralPk)
    }

    /**
     * Encrypts [plaintext] with the Double Ratchet of the session registered
     * under [sessionId], returning `header || ciphertext`. An id with no
     * session behind it fails with CoreException.NoSession rather than
     * yielding anything a caller could mistake for ciphertext.
     */
    fun encryptMessage(sessionId: ULong, plaintext: ByteArray): ByteArray {
        return requireCore().encryptMessage(sessionId, plaintext)
    }

    /**
     * Decrypts [message] (as produced by [encryptMessage]) with the session
     * registered under [sessionId]. Authentication failure surfaces as
     * CoreException and leaves the ratchet untouched — Rust snapshots and
     * rolls back, which is the F-1 guarantee, and this wrapper adds no
     * mutation that could weaken it. An unknown id fails with
     * CoreException.NoSession.
     *
     * Which local session an inbound message belongs to is not decided here:
     * the id travels in no part of the message, so the caller must already
     * know it.
     */
    fun decryptMessage(sessionId: ULong, message: ByteArray): ByteArray {
        return requireCore().decryptMessage(sessionId, message)
    }

    /**
     * Derives this device's own lookup handle for the session with the peer
     * whose 32-byte X25519 identity public key is [peerIdentityPk].
     *
     * Pure: it needs no open store, so unlike the methods above it does not
     * require [openEncryptedDb]. A wrong-length key raises CoreException rather
     * than being truncated or padded into a plausible-looking handle.
     *
     * The result is a truncation and therefore not collision-free, but the
     * caller does not have to police that: Rust stores the peer's full public
     * key with the session and never overwrites an occupied handle. A clash
     * surfaces as CoreException.SessionIdCollision, and re-establishing a live
     * session as CoreException.SessionAlreadyExists.
     */
    fun localSessionHandle(peerIdentityPk: ByteArray): ULong {
        return uniffi.arcium_core.localSessionHandle(peerIdentityPk)
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

    /**
     * The open Rust handle, or IllegalStateException — the same fail-loud
     * contract the identity methods above state inline, shared by the six
     * messaging methods so the message cannot drift between them.
     */
    private fun requireCore(): uniffi.arcium_core.ArciumCore =
        core ?: error("encrypted DB is not open — call openEncryptedDb() first")
}
