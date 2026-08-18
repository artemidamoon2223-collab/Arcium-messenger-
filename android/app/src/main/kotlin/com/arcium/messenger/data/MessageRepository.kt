package com.arcium.messenger.data

import com.arcium.messenger.ArciumApp
import com.arcium.messenger.ffi.ArciumCoreWrapper

/** Length of the initiator handshake: `identity_pk(32) || ephemeral_pk(32)`. */
private const val HANDSHAKE_BYTES = 64
private const val PUBLIC_KEY_BYTES = 32

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
 * Every peer is named here by its full 32-byte X25519 identity public key, never
 * by a phone number: the phone hash is the PSI matching token and is pinned to
 * the deployed Arcium circuit, so reusing it here would tie message routing to
 * the circuit version and put a value reversible by enumeration into the session
 * table. Handles are derived, never invented, and every one is claimed through
 * [MessagingSessionRegistry] so a truncation collision fails loudly.
 *
 * ## No transport
 *
 * This class encrypts. It does not send, and nothing here does: `mobile-ffi`
 * exports no transport surface, so there is no way to deliver a ciphertext to a
 * peer. Producing ciphertext and delivering it are therefore separate, and no
 * method returns success for a delivery that did not happen. The bytes returned
 * by [startSessionAsInitiator] and [encryptForPeer], and the bytes consumed by
 * [acceptSessionAsResponder] and [decryptFromPeer], have to cross to the peer by
 * some channel this layer does not provide.
 *
 * CoreException from Rust propagates unchanged — it is never caught, flattened
 * into a Boolean or null, or turned into a success value.
 */
class MessageRepository(
    private val core: ArciumCoreWrapper = ArciumApp.core,
    private val sessions: MessagingSessionRegistry = ArciumApp.sessions,
) {

    /**
     * Generates and persists this device's prekeys so peers can open sessions
     * against it. Overwrites any previous prekeys — Rust has no "already
     * established" guard.
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
     * Local handle for [peerIdentityPk], derived and claimed. Throws
     * IllegalStateException if a different peer already holds that handle.
     */
    fun handleFor(peerIdentityPk: ByteArray): ULong {
        requirePublicKey(peerIdentityPk)
        return sessions.claim(core.localSessionHandle(peerIdentityPk), peerIdentityPk)
    }

    /**
     * Opens a session with [peerIdentityPk] as the X3DH initiator, against that
     * peer's [peerPrekeyBundle].
     *
     * Returns `identity_pk(32) || ephemeral_pk(32)` — the bytes the peer needs
     * for [acceptSessionAsResponder]. **Returning them is not sending them.**
     */
    fun startSessionAsInitiator(peerIdentityPk: ByteArray, peerPrekeyBundle: ByteArray): ByteArray {
        return core.establishSessionInitiator(handleFor(peerIdentityPk), peerPrekeyBundle)
    }

    /**
     * Opens a session with [peerIdentityPk] as the X3DH responder, from the
     * 64-byte [initiatorHandshake] that peer's [startSessionAsInitiator]
     * produced. Requires [publishOwnPrekeys] to have run here first.
     *
     * Initiator and responder are distinct X3DH roles; neither call substitutes
     * for the other.
     */
    fun acceptSessionAsResponder(peerIdentityPk: ByteArray, initiatorHandshake: ByteArray) {
        check(initiatorHandshake.size == HANDSHAKE_BYTES) {
            "initiator handshake must be $HANDSHAKE_BYTES bytes " +
                "(identity_pk || ephemeral_pk), got ${initiatorHandshake.size}"
        }
        core.establishSessionResponder(
            handleFor(peerIdentityPk),
            initiatorHandshake.copyOfRange(0, PUBLIC_KEY_BYTES),
            initiatorHandshake.copyOfRange(PUBLIC_KEY_BYTES, HANDSHAKE_BYTES),
        )
    }

    /**
     * Encrypts [plaintext] for [peerIdentityPk] and returns `header || ciphertext`.
     *
     * **This does not transmit anything.** With no session open for that peer,
     * Rust fails with CoreException.NoSession rather than returning bytes a
     * caller could mistake for a delivered message.
     */
    fun encryptForPeer(peerIdentityPk: ByteArray, plaintext: ByteArray): ByteArray {
        return core.encryptMessage(handleFor(peerIdentityPk), plaintext)
    }

    /**
     * Decrypts a [message] received from [peerIdentityPk].
     *
     * The caller must already know which peer sent it: the handle appears
     * nowhere in the message, so nothing in the ciphertext identifies the
     * session. Authentication failure surfaces as CoreException and leaves the
     * ratchet state untouched.
     */
    fun decryptFromPeer(peerIdentityPk: ByteArray, message: ByteArray): ByteArray {
        return core.decryptMessage(handleFor(peerIdentityPk), message)
    }

    private fun requirePublicKey(peerIdentityPk: ByteArray) {
        check(peerIdentityPk.size == PUBLIC_KEY_BYTES) {
            "peer identity public key must be $PUBLIC_KEY_BYTES bytes, got ${peerIdentityPk.size}"
        }
    }
}
