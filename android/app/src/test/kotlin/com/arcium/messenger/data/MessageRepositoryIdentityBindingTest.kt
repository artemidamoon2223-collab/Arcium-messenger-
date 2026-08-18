package com.arcium.messenger.data

import com.arcium.messenger.ffi.ArciumCoreWrapper
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

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

    /** A structurally valid bundle whose leading identity is [identity]. */
    private fun bundle(identity: ByteArray, withOneTimePrekey: Boolean = false): ByteArray {
        val size = if (withOneTimePrekey) 193 else 161
        return ByteArray(size) { 7 }.also { identity.copyInto(it, 0) }
    }

    /** A structurally valid 64-byte handshake whose leading identity is [identity]. */
    private fun handshake(identity: ByteArray): ByteArray =
        ByteArray(64) { 7 }.also { identity.copyInto(it, 0) }

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

        for (size in listOf(0, 32, 160, 162, 192, 194)) {
            val malformed = ByteArray(size).also { if (size >= 32) alice.copyInto(it, 0) }
            assertThrows(
                "a $size-byte bundle must be refused",
                IllegalStateException::class.java,
            ) { repo().startSessionAsInitiator(alice, malformed) }
        }
    }

    @Test
    fun `responder rejects a handshake that is not exactly 64 bytes`() {
        val alice = key(1)

        for (size in listOf(0, 32, 63, 65, 128)) {
            val malformed = ByteArray(size).also { if (size >= 32) alice.copyInto(it, 0) }
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

        // 193-byte form must pass the length check and fail on identity, proving
        // the length gate does not reject the with-OTP layout.
        val error = assertThrows(IllegalStateException::class.java) {
            repo().startSessionAsInitiator(bob, bundle(alice, withOneTimePrekey = true))
        }
        assertTrue(error.message!!.contains("peer identity mismatch"))
    }
}
