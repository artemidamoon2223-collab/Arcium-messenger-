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
    // `sessionId` is a local lookup handle into the Rust session store, not a
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
    fun establishSessionResponder(sessionId: ULong, initiatorHandshake: ByteArray) {
        requireCore().establishSessionResponder(sessionId, initiatorHandshake)
    }

    // ── Durable messaging (S2-B2) ────────────────────────────────────────────
    //
    // Rust owns every session transition. Each call below loads the session
    // from the encrypted store, advances it, and commits the new state together
    // with the message record before returning anything; Kotlin holds no
    // session state and never retries an encryption. Specification:
    // docs/S2-B2-DURABLE-MESSAGING.md.

    /**
     * Sends the logical message [clientMessageId] (the caller's own id for it,
     * 1 to 64 bytes, unique per logical message). The first call encrypts
     * [plaintext] and commits it to the outbox before returning `Sent`; its
     * `wire` bytes are what must be sent, now and on every retransmission.
     * Any later call with the same id encrypts nothing and returns the stored
     * message (`AlreadyPending`), `AlreadyAcknowledged` or `Abandoned` — so
     * after a crash or CoreException.CommitOutcomeUnknown, call again with
     * the same id.
     */
    fun sendMessage(
        sessionId: ULong,
        clientMessageId: ByteArray,
        plaintext: ByteArray,
    ): uniffi.arcium_core.SendResult {
        return requireCore().sendMessage(sessionId, clientMessageId, plaintext)
    }

    /**
     * Deletes the session under [sessionId], so a new session with that peer
     * can be established. Only a session with nothing left to settle is
     * removed: it fails with CoreException.SessionEstablished once a message
     * from the peer was accepted, and with CoreException.PendingOutgoing
     * while outgoing messages are neither acknowledged nor abandoned.
     */
    fun removeSession(sessionId: ULong) {
        requireCore().removeSession(sessionId)
    }

    /** Committed, unacknowledged outgoing messages for [sessionId], in send order. */
    fun pendingOutgoing(sessionId: ULong): List<uniffi.arcium_core.OutgoingMessage> {
        return requireCore().pendingOutgoing(sessionId)
    }

    /** Drops an outgoing message once delivery is confirmed. Idempotent. */
    fun acknowledgeOutgoing(sessionId: ULong, messageId: ByteArray): Boolean {
        return requireCore().acknowledgeOutgoing(sessionId, messageId)
    }

    /**
     * Stops retransmitting an outgoing message without a delivery
     * confirmation; its logical id is then reported as `Abandoned`. The peer
     * may or may not have it. Idempotent.
     */
    fun abandonOutgoing(sessionId: ULong, messageId: ByteArray): Boolean {
        return requireCore().abandonOutgoing(sessionId, messageId)
    }

    /**
     * Decrypts a peer's `wire` bytes. A new message is committed as undelivered
     * before its plaintext is returned; a message seen before comes back as
     * `Duplicate` without advancing the ratchet. Authentication failure throws
     * CoreException and writes nothing (F-1).
     */
    fun receiveMessage(sessionId: ULong, message: ByteArray): uniffi.arcium_core.ReceiveResult {
        return requireCore().receiveMessage(sessionId, message)
    }

    /**
     * Committed incoming messages for [sessionId] not yet acknowledged.
     * Delivery to the app is at least once: after a crash a message shown but
     * not acknowledged is listed again, identified by its `messageId`.
     */
    fun pendingIncoming(sessionId: ULong): List<uniffi.arcium_core.IncomingMessage> {
        return requireCore().pendingIncoming(sessionId)
    }

    /**
     * Records that the app has durably processed an incoming message; its
     * stored plaintext is erased. Call only once the message is safe on the
     * app side. Idempotent.
     */
    fun acknowledgeIncoming(sessionId: ULong, messageId: ByteArray): Boolean {
        return requireCore().acknowledgeIncoming(sessionId, messageId)
    }

    /**
     * After CoreException.CommitOutcomeUnknown: reports what the store holds
     * and lets the session continue. Null if it was not unresolved.
     */
    fun recoverSession(sessionId: ULong): uniffi.arcium_core.RecoveryReport? {
        return requireCore().recoverSession(sessionId)
    }

    /** The initiator handshake stored with [sessionId], for sending again. */
    fun initiatorHandshake(sessionId: ULong): ByteArray? {
        return requireCore().initiatorHandshake(sessionId)
    }

    /** Whether a session is stored under [sessionId]. */
    fun hasSession(sessionId: ULong): Boolean {
        return requireCore().hasSession(sessionId)
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

    /** Releases the Rust store handle. Everything committed stays on disk. */
    fun closeEncryptedDb() {
        val previous = core
        core = null
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
