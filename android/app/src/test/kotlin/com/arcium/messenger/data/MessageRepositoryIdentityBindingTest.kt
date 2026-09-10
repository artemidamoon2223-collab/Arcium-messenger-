package com.arcium.messenger.data

import com.arcium.messenger.ffi.ArciumCoreWrapper
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `ARCIUM_X3DH_FORMAT_V1` sizes, restated here because the production copies are
 * file-private in `MessageRepository.kt`. Restating them is deliberate: if the
 * production constants ever change, these must be updated too and the tests below
 * will fail loudly rather than following along silently.
 */
private const val BUNDLE_BYTES = 204
private const val HANDSHAKE_BYTES = 84
private const val IDENTITY_OFFSET = 4

/**
 * Covers the identity binding between the peer the caller names and the peer
 * whose identity Rust would actually key the session from.
 *
 * ## What is and is not covered here
 *
 * Only the **rejection** paths. Every check below runs before the first FFI
 * call, so a mismatch throws without the native library ever being touched,
 * which is exactly what makes it testable off-device.
 *
 * The **acceptance** paths are not covered: a matching identity proceeds to
 * `localSessionHandle`, which crosses JNA into `libarcium_core`. Reaching it
 * from a JVM unit test would need either the native library loaded or a mocking
 * framework standing in for the wrapper, and neither is set up here. That gap is
 * real: these tests prove bad input is refused, not that good input is accepted.
 *
 * The repository is built with its own wrapper rather than the process-wide
 * one, since `ArciumApp` never runs in a unit test.
 *
 * Session ownership itself is not asserted here any more: it lives in the Rust
 * `SessionManager`, and the tests that prove a rejected or failed establishment
 * leaves nothing behind are in `crates/mobile-ffi`.
 */
class MessageRepositoryIdentityBindingTest {

    private fun key(byte: Byte) = ByteArray(32) { byte }

    /**
     * A structurally valid `PREKEY_BUNDLE_V1` carrying [identity].
     *
     * Always 204 bytes: v1 zero-fills the one-time prekey fields when absent
     * rather than shortening the structure, so [withOneTimePrekey] flips a flag
     * and a tail, never the length.
     */
    private fun bundle(identity: ByteArray, withOneTimePrekey: Boolean = false): ByteArray {
        val b = ByteArray(BUNDLE_BYTES) { 7 }
        b[0] = 0x01 // protocol_version
        b[1] = 0x01 // cipher_suite
        b[2] = if (withOneTimePrekey) 0x01 else 0x00
        b[3] = 0x00 // reserved
        identity.copyInto(b, IDENTITY_OFFSET)
        if (!withOneTimePrekey) b.fill(0, 164, BUNDLE_BYTES)
        return b
    }

    /** A structurally valid 84-byte `INITIATOR_HANDSHAKE_V1` carrying [identity]. */
    private fun handshake(identity: ByteArray): ByteArray {
        val h = ByteArray(HANDSHAKE_BYTES) { 7 }
        h[0] = 0x01
        h[1] = 0x01
        h[2] = 0x00 // used_otp = 0
        h[3] = 0x00
        identity.copyInto(h, IDENTITY_OFFSET)
        h.fill(0, 76, HANDSHAKE_BYTES)
        return h
    }

    private fun repo() = MessageRepository(ArciumCoreWrapper())

    @Test
    fun `initiator rejects a bundle whose identity is not the named peer`() {
        val alice = key(1)
        val bob = key(2)

        val error = assertThrows(IllegalStateException::class.java) {
            repo().startSessionAsInitiator(peerIdentityPk = bob, peerPrekeyBundle = bundle(alice))
        }

        assertTrue(
            "message should explain the mismatch, got: ${error.message}",
            error.message!!.contains("peer identity mismatch"),
        )
    }

    @Test
    fun `responder rejects a handshake whose identity is not the named peer`() {
        val alice = key(1)
        val bob = key(2)

        val error = assertThrows(IllegalStateException::class.java) {
            repo().acceptSessionAsResponder(peerIdentityPk = bob, initiatorHandshake = handshake(alice))
        }

        assertTrue(
            "message should explain the mismatch, got: ${error.message}",
            error.message!!.contains("peer identity mismatch"),
        )
    }

    /**
     * A one-byte difference is still a different peer. Guards against a check
     * that only compares a prefix or a length.
     */
    @Test
    fun `initiator rejects an identity differing in a single byte`() {
        val named = key(1)
        val carried = key(1).also { it[31] = 2 }

        assertThrows(IllegalStateException::class.java) {
            repo().startSessionAsInitiator(named, bundle(carried))
        }
    }

    @Test
    fun `initiator rejects a bundle of unrecognised length before comparing identity`() {
        val alice = key(1)

        for (size in listOf(0, 32, 161, 193, 203, 205)) {
            val malformed = ByteArray(size).also { if (size >= 36) alice.copyInto(it, IDENTITY_OFFSET) }
            assertThrows(
                "a $size-byte bundle must be refused",
                IllegalStateException::class.java,
            ) { repo().startSessionAsInitiator(alice, malformed) }
        }
    }

    @Test
    fun `responder rejects a handshake that is not exactly 84 bytes`() {
        val alice = key(1)

        for (size in listOf(0, 32, 64, 83, 85, 168)) {
            val malformed = ByteArray(size).also { if (size >= 36) alice.copyInto(it, IDENTITY_OFFSET) }
            assertThrows(
                "a $size-byte handshake must be refused",
                IllegalStateException::class.java,
            ) { repo().acceptSessionAsResponder(alice, malformed) }
        }
    }

    /**
     * An Ed25519 signing key is also 32 bytes, so passing one where the X25519 DH
     * identity belongs type-checks. It must still be refused, on content.
     */
    @Test
    fun `a wrong-but-same-length key is refused rather than accepted on size alone`() {
        val dhIdentity = key(1)
        val someOther32ByteKey = key(0x5A)

        assertThrows(IllegalStateException::class.java) {
            repo().startSessionAsInitiator(someOther32ByteKey, bundle(dhIdentity))
        }
    }

    @Test
    fun `a peer key of the wrong size is refused`() {
        val alice = key(1)

        for (size in listOf(0, 31, 33, 64)) {
            assertThrows(
                "a $size-byte peer key must be refused",
                IllegalStateException::class.java,
            ) { repo().startSessionAsInitiator(ByteArray(size), bundle(alice)) }
        }
    }

    @Test
    fun `a bundle with a one-time prekey is accepted structurally and still identity-checked`() {
        val alice = key(1)
        val bob = key(2)

        // The with-OTP form must pass the length check and fail on identity,
        // proving the flag byte does not disturb the length gate.
        val error = assertThrows(IllegalStateException::class.java) {
            repo().startSessionAsInitiator(bob, bundle(alice, withOneTimePrekey = true))
        }
        assertTrue(error.message!!.contains("peer identity mismatch"))
    }
}
