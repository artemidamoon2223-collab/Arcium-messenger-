package com.arcium.messenger.data

import com.arcium.messenger.ArciumApp
import com.arcium.messenger.ffi.ArciumCoreWrapper

private const val PUBLIC_KEY_BYTES = 32

/**
 * `INITIATOR_HANDSHAKE_V1`, always exactly this long:
 * `protocol_version(1) || cipher_suite(1) || flags(1) || reserved(1) ||
 * identity_dh_pk(32) || ephemeral_pk(32) || spk_id(8) || opk_id(8)`.
 */
private const val HANDSHAKE_BYTES = 84

/**
 * `PREKEY_BUNDLE_V1`, always exactly this long:
 * `protocol_version(1) || cipher_suite(1) || flags(1) || reserved(1) ||
 * identity_dh_pk(32) || signing_pk(32) || signed_prekey_pk(32) ||
 * spk_signature(64) || opk_id(8) || opk_pk(32)`.
 *
 * One length, not two: v1 zero-fills the one-time prekey fields when absent
 * rather than shortening the structure, so there is no length to branch on.
 */
private const val BUNDLE_BYTES = 204

/**
 * Offset of the X25519 DH identity in both wire structures. Both carry the same
 * four-byte header, so the identity sits at the same place in each — named once
 * here so the four call sites below cannot drift apart.
 */
private const val IDENTITY_OFFSET = 4
private const val IDENTITY_END = IDENTITY_OFFSET + PUBLIC_KEY_BYTES

data class Message(
    val id: String,
    val sessionId: ULong,
    val senderKey: ByteArray,
    val ciphertext: ByteArray,
    val timestampMs: Long,
    val isMine: Boolean,
)

/**
 * Encrypts and decrypts messages for a peer, addressing the Rust session by a
 * handle derived from that peer's identity public key.
 *
 * ## Which key `peerIdentityPk` is
 *
 * Every `peerIdentityPk` here is the peer's **32-byte X25519 DH identity public
 * key** — the one X3DH performs key agreement with, `Identity.dhPublicKeyBytes()`
 * on the Rust side. Three other 32-byte values exist nearby and none of them
 * works here:
 *
 * - the **Ed25519** signing key from `Identity.publicKeyBytes()`, which is a
 *   different key of the same length and sits at bytes 36..68 of a prekey bundle;
 * - the peer's ratchet DH key from a message header, which changes every step;
 * - `hash_contact(phone)`, which is the PSI matching token, not an identity.
 *
 * Passing the wrong one does not fail cleanly at the type level — every candidate
 * is a 32-byte array — so the checks below compare the caller's key against the
 * identity Rust will actually use, rather than trusting the argument.
 *
 * ## Identity binding
 *
 * Rust does not take the peer identity from the argument: it reads it out of the
 * prekey bundle for an initiator, and out of the handshake for a responder. If
 * the two disagree, the caller believes it is talking to B while the session is
 * cryptographically with A. Both entry points therefore require the caller's key
 * to equal the identity carried in those bytes, and fail before any session is
 * created.
 *
 * The phone hash is never used: it is the PSI matching token, pinned to the
 * deployed Arcium circuit, so reusing it would tie message routing to the circuit
 * version and put a value reversible by enumeration into the session table.
 *
 * ## Ownership lives in Rust
 *
 * This class keeps no session bookkeeping of its own. Rust is the single
 * authority on which sessions exist and who owns them: the encrypted store
 * holds each session with the peer's full public key, and an occupied handle is
 * never reused, surfacing `CoreException.SessionAlreadyExists` or
 * `CoreException.SessionIdCollision`. Sessions and undelivered messages survive
 * process death (S2-B2, docs/S2-B2-DURABLE-MESSAGING.md). A Kotlin mirror of that state used to
 * exist and was removed, because it could record an owner before the FFI call
 * that would have created the session succeeded — and then keep that record when
 * the call failed.
 *
 * ## No transport
 *
 * This class encrypts. It does not send, and nothing here does: `mobile-ffi`
 * exports no transport surface, so there is no way to deliver a ciphertext to a
 * peer. Producing ciphertext and delivering it are therefore separate, and no
 * method returns success for a delivery that did not happen. The bytes returned
 * by [startSessionAsInitiator] and [sendToPeer], and the bytes consumed by
 * [acceptSessionAsResponder] and [receiveFromPeer], have to cross to the peer by
 * some channel this layer does not provide.
 *
 * CoreException from Rust propagates unchanged — it is never caught, flattened
 * into a Boolean or null, or turned into a success value.
 */
class MessageRepository(
    private val core: ArciumCoreWrapper = ArciumApp.core,
) {

    /**
     * Generates and persists this device's prekeys so peers can open sessions
     * against it. Overwrites any previous prekeys — Rust has no "already
     * established" guard — which invalidates every bundle already handed out:
     * handshakes built from those are refused as stale rather than silently
     * deriving a key the peer cannot match.
     */
    fun publishOwnPrekeys() {
        core.establishPrekeys()
    }

    /**
     * This device's prekey bundle, for a peer to feed to
     * [startSessionAsInitiator] on its own device. Fails with CoreException if
     * [publishOwnPrekeys] never ran. Delivering it is not handled here.
     */
    fun ownPrekeyBundle(): ByteArray = core.exportPrekeyBundle()

    /**
     * Local handle for [peerIdentityPk]: a pure derivation with no bookkeeping.
     * Calling it records nothing and reserves nothing, so a handle only ever
     * becomes owned when Rust actually creates the session.
     */
    fun handleFor(peerIdentityPk: ByteArray): ULong {
        requirePublicKey(peerIdentityPk)
        return core.localSessionHandle(peerIdentityPk)
    }

    /**
     * Opens a session with [peerIdentityPk] as the X3DH initiator, against that
     * peer's [peerPrekeyBundle].
     *
     * [peerIdentityPk] must equal the bundle's own identity (the X25519 DH key at
     * [IDENTITY_OFFSET]), or this throws IllegalStateException having created no
     * session.
     *
     * Returns the 84-byte `INITIATOR_HANDSHAKE_V1` the peer needs for
     * [acceptSessionAsResponder]. **Returning it is not sending it.**
     */
    fun startSessionAsInitiator(peerIdentityPk: ByteArray, peerPrekeyBundle: ByteArray): ByteArray {
        // Before anything is created: the bundle's own identity is what
        // Rust will run X3DH against, so it — not the argument — decides who this
        // session is with. Disagreement means the caller is about to file a session
        // with A under B's handle, and there is no safe way to guess which side is
        // right, so neither is used.
        requireBundleIdentityMatches(peerIdentityPk, peerPrekeyBundle)
        return core.establishSessionInitiator(handleFor(peerIdentityPk), peerPrekeyBundle)
    }

    /**
     * Opens a session with [peerIdentityPk] as the X3DH responder, from the
     * 84-byte [initiatorHandshake] that peer's [startSessionAsInitiator]
     * produced. Requires [publishOwnPrekeys] to have run here first.
     *
     * [peerIdentityPk] must equal the identity the handshake carries, or this
     * throws IllegalStateException having created no session — otherwise a
     * session established with one peer could be recorded under another peer's
     * handle.
     *
     * Initiator and responder are distinct X3DH roles; neither call substitutes
     * for the other.
     */
    fun acceptSessionAsResponder(peerIdentityPk: ByteArray, initiatorHandshake: ByteArray) {
        // Same binding as the initiator path, for the same reason: the identity
        // Rust will key the session from is the one inside the handshake.
        requireHandshakeIdentityMatches(peerIdentityPk, initiatorHandshake)
        // The whole structure goes across: the handshake also names which signed
        // prekey and which one-time prekey it used, and Rust needs both to decide
        // whether this device can still answer it. Slicing out the two keys here,
        // as the pre-v1 API did, would discard exactly that.
        core.establishSessionResponder(handleFor(peerIdentityPk), initiatorHandshake)
    }

    /**
     * Sends the logical message [clientMessageId] (the app's own id for it,
     * 1 to 64 bytes, unique per logical message) to [peerIdentityPk]. The first
     * call encrypts [plaintext] and commits it to the durable outbox with the
     * new session state; repeating the call with the same id — after a crash,
     * a restart or an unknown commit outcome — returns what was committed and
     * never encrypts the message a second time.
     *
     * **This does not transmit anything.** Pending bytes are in [pendingOutgoingTo].
     */
    fun sendToPeer(
        peerIdentityPk: ByteArray,
        clientMessageId: ByteArray,
        plaintext: ByteArray,
    ): uniffi.arcium_core.SendResult {
        return core.sendMessage(handleFor(peerIdentityPk), clientMessageId, plaintext)
    }

    /**
     * Deletes the session with [peerIdentityPk] — for example after the peer
     * refused its handshake — so a new one can be established. Returns the
     * unacknowledged outgoing messages it discarded.
     */
    fun removeSessionWith(peerIdentityPk: ByteArray): List<uniffi.arcium_core.OutgoingMessage> {
        return core.removeSession(handleFor(peerIdentityPk))
    }

    /** Committed messages to [peerIdentityPk] not yet confirmed delivered, in send order. */
    fun pendingOutgoingTo(peerIdentityPk: ByteArray): List<uniffi.arcium_core.OutgoingMessage> {
        return core.pendingOutgoing(handleFor(peerIdentityPk))
    }

    /** Called once delivery of [messageId] is confirmed. Idempotent. */
    fun confirmDelivered(peerIdentityPk: ByteArray, messageId: ByteArray): Boolean {
        return core.acknowledgeOutgoing(handleFor(peerIdentityPk), messageId)
    }

    /**
     * Accepts a [message] received from [peerIdentityPk].
     *
     * The caller must already know which peer sent it: the handle appears
     * nowhere in the message. A new message is committed as undelivered before
     * its plaintext is returned; one seen before is reported as a duplicate and
     * does not advance the ratchet. Authentication failure surfaces as
     * CoreException and writes nothing.
     */
    fun receiveFromPeer(peerIdentityPk: ByteArray, message: ByteArray): uniffi.arcium_core.ReceiveResult {
        return core.receiveMessage(handleFor(peerIdentityPk), message)
    }

    /** Committed messages from [peerIdentityPk] not yet shown, in receive order. */
    fun pendingIncomingFrom(peerIdentityPk: ByteArray): List<uniffi.arcium_core.IncomingMessage> {
        return core.pendingIncoming(handleFor(peerIdentityPk))
    }

    /**
     * Called once [messageId] is durably processed on the app side (stored or
     * shown); acknowledging earlier can lose it. Idempotent.
     */
    fun markShown(peerIdentityPk: ByteArray, messageId: ByteArray): Boolean {
        return core.acknowledgeIncoming(handleFor(peerIdentityPk), messageId)
    }

    private fun requirePublicKey(peerIdentityPk: ByteArray) {
        check(peerIdentityPk.size == PUBLIC_KEY_BYTES) {
            "peer identity public key must be $PUBLIC_KEY_BYTES bytes, got ${peerIdentityPk.size}"
        }
    }

    /**
     * Requires [peerPrekeyBundle] to be a well-formed bundle whose identity — the
     * X25519 DH key at [IDENTITY_OFFSET], the one Rust runs X3DH against — is
     * exactly [peerIdentityPk]. Throws before any session is created.
     */
    private fun requireBundleIdentityMatches(peerIdentityPk: ByteArray, peerPrekeyBundle: ByteArray) {
        requirePublicKey(peerIdentityPk)
        check(peerPrekeyBundle.size == BUNDLE_BYTES) {
            "prekey bundle must be $BUNDLE_BYTES bytes, got ${peerPrekeyBundle.size}"
        }
        requireSameIdentity(
            expected = peerIdentityPk,
            carried = peerPrekeyBundle.copyOfRange(IDENTITY_OFFSET, IDENTITY_END),
            source = "prekey bundle",
        )
    }

    /**
     * Requires [initiatorHandshake] to be exactly 84 bytes whose carried identity
     * is exactly [peerIdentityPk]. Throws before any session is created, so a
     * session established with one peer can never be recorded under another
     * peer's identity.
     */
    private fun requireHandshakeIdentityMatches(peerIdentityPk: ByteArray, initiatorHandshake: ByteArray) {
        requirePublicKey(peerIdentityPk)
        check(initiatorHandshake.size == HANDSHAKE_BYTES) {
            "initiator handshake must be $HANDSHAKE_BYTES bytes, " +
                "got ${initiatorHandshake.size}"
        }
        requireSameIdentity(
            expected = peerIdentityPk,
            carried = initiatorHandshake.copyOfRange(IDENTITY_OFFSET, IDENTITY_END),
            source = "initiator handshake",
        )
    }

    private fun requireSameIdentity(expected: ByteArray, carried: ByteArray, source: String) {
        check(expected.contentEquals(carried)) {
            "peer identity mismatch: the $source carries ${carried.toHex()}, but the caller " +
                "named ${expected.toHex()}. Rust would key the session from the $source, so " +
                "continuing would record a session with one peer under another peer's handle. " +
                "Note both are 32 bytes: check an Ed25519 signing key was not passed where the " +
                "X25519 DH identity key belongs."
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
