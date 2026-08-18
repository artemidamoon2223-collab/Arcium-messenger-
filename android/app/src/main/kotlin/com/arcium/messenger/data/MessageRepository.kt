package com.arcium.messenger.data

import com.arcium.messenger.ArciumApp
import com.arcium.messenger.ffi.ArciumCoreWrapper

/** Length of the initiator handshake: `identity_pk(32) || ephemeral_pk(32)`. */
private const val HANDSHAKE_BYTES = 64
private const val PUBLIC_KEY_BYTES = 32

/**
 * Prekey bundle lengths, from the Rust layout
 * `identity_pk(32) || signing_pk(32) || signed_prekey_pk(32) || signature(64) ||
 * has_otp(1) || [one_time_prekey_pk(32)]` — 161 without a one-time prekey, 193
 * with one. Rust rejects every other length.
 */
private const val BUNDLE_BYTES_NO_OTP = 161
private const val BUNDLE_BYTES_WITH_OTP = 193

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
 *   different key of the same length and sits at bytes 32..64 of a prekey bundle;
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
 * this class claimed a handle for the caller's `peerIdentityPk` while Rust built
 * the session from different bytes, the registry would record a session with B
 * that is cryptographically a session with A. Both entry points therefore require
 * the caller's key to equal the identity carried in those bytes, and fail before
 * anything is claimed or created.
 *
 * The phone hash is never used: it is the PSI matching token, pinned to the
 * deployed Arcium circuit, so reusing it would tie message routing to the circuit
 * version and put a value reversible by enumeration into the session table.
 * Handles are derived, never invented, and every one is claimed through
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
     * [peerIdentityPk] must equal the bundle's own identity (its first 32 bytes,
     * the X25519 DH key), or this throws IllegalStateException having claimed no
     * handle and created no session.
     *
     * Returns `identity_pk(32) || ephemeral_pk(32)` — the bytes the peer needs
     * for [acceptSessionAsResponder]. **Returning them is not sending them.**
     */
    fun startSessionAsInitiator(peerIdentityPk: ByteArray, peerPrekeyBundle: ByteArray): ByteArray {
        // Before anything is claimed or created: the bundle's own identity is what
        // Rust will run X3DH against, so it — not the argument — decides who this
        // session is with. Disagreement means the caller is about to file a session
        // with A under B's handle, and there is no safe way to guess which side is
        // right, so neither is used.
        requireBundleIdentityMatches(peerIdentityPk, peerPrekeyBundle)
        return core.establishSessionInitiator(handleFor(peerIdentityPk), peerPrekeyBundle)
    }

    /**
     * Opens a session with [peerIdentityPk] as the X3DH responder, from the
     * 64-byte [initiatorHandshake] that peer's [startSessionAsInitiator]
     * produced. Requires [publishOwnPrekeys] to have run here first.
     *
     * [peerIdentityPk] must equal the handshake's leading 32 bytes, or this
     * throws IllegalStateException having claimed no handle and created no
     * session — otherwise a session established with one peer could be filed
     * under another peer's handle.
     *
     * Initiator and responder are distinct X3DH roles; neither call substitutes
     * for the other.
     */
    fun acceptSessionAsResponder(peerIdentityPk: ByteArray, initiatorHandshake: ByteArray) {
        // Same binding as the initiator path, for the same reason: the identity
        // Rust will key the session from is the one inside the handshake.
        requireHandshakeIdentityMatches(peerIdentityPk, initiatorHandshake)
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

    /**
     * Requires [peerPrekeyBundle] to be a well-formed bundle whose identity — its
     * first 32 bytes, the X25519 DH key Rust runs X3DH against — is exactly
     * [peerIdentityPk]. Throws before any handle is claimed or session created.
     */
    private fun requireBundleIdentityMatches(peerIdentityPk: ByteArray, peerPrekeyBundle: ByteArray) {
        requirePublicKey(peerIdentityPk)
        check(
            peerPrekeyBundle.size == BUNDLE_BYTES_NO_OTP ||
                peerPrekeyBundle.size == BUNDLE_BYTES_WITH_OTP,
        ) {
            "prekey bundle must be $BUNDLE_BYTES_NO_OTP or $BUNDLE_BYTES_WITH_OTP bytes, " +
                "got ${peerPrekeyBundle.size}"
        }
        requireSameIdentity(
            expected = peerIdentityPk,
            carried = peerPrekeyBundle.copyOfRange(0, PUBLIC_KEY_BYTES),
            source = "prekey bundle",
        )
    }

    /**
     * Requires [initiatorHandshake] to be exactly 64 bytes whose leading identity
     * is exactly [peerIdentityPk]. Throws before any handle is claimed or session
     * created, so a session established with one peer can never be filed under
     * another peer's identity.
     */
    private fun requireHandshakeIdentityMatches(peerIdentityPk: ByteArray, initiatorHandshake: ByteArray) {
        requirePublicKey(peerIdentityPk)
        check(initiatorHandshake.size == HANDSHAKE_BYTES) {
            "initiator handshake must be $HANDSHAKE_BYTES bytes " +
                "(identity_pk || ephemeral_pk), got ${initiatorHandshake.size}"
        }
        requireSameIdentity(
            expected = peerIdentityPk,
            carried = initiatorHandshake.copyOfRange(0, PUBLIC_KEY_BYTES),
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
