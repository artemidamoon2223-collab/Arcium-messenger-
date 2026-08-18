package com.arcium.messenger.ffi

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.arcium.messenger.data.MessageRepository
import java.io.File
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The first test in this repository that executes the whole messaging chain on
 * an Android runtime:
 *
 *     Android → ArciumCoreWrapper / MessageRepository → generated UniFFI Kotlin
 *     → JNA → packaged libarcium_core.so → Rust X3DH + Double Ratchet
 *
 * Everything else so far proves compilation and packaging. This proves the
 * bridge actually works, because a two-peer handshake and a bidirectional
 * round trip cannot succeed unless the native library loaded and every layer
 * between passed real bytes through.
 *
 * ## Deliberately excluded
 *
 * No Tor, no PSI, no network: the peers exchange bytes by returning them inside
 * this test, which is exactly what the production code does today — it produces
 * and consumes those bytes and never delivers them. No mocks and no fake FFI:
 * a stand-in would remove the only thing being proved. No reflection into Rust
 * state; every assertion goes through the public API.
 *
 * `MasterKeyProvider` and the Android Keystore are also out of scope. This is a
 * test of the FFI and session runtime, so the stores are opened with fixed test
 * key bytes — test fixtures, not secrets, and not the provisioning path.
 *
 * ## A trap this test is careful about
 *
 * `generateAndSaveIdentity()` returns the **Ed25519** signing key. Messaging is
 * keyed by the **X25519** DH identity, and both are 32 bytes, so substituting
 * one for the other type-checks and fails only at runtime. Neither peer's
 * messaging identity is taken from that return value here. Bob's comes from his
 * real exported bundle, Alice's from the real handshake she produced — the same
 * bytes Rust itself keys the session from.
 */
@RunWith(AndroidJUnit4::class)
class TwoPeerMessagingInstrumentationTest {

    private companion object {
        const val PUBLIC_KEY_BYTES = 32
        const val HANDSHAKE_BYTES = 64
        const val BUNDLE_BYTES_NO_OTP = 161
        const val BUNDLE_BYTES_WITH_OTP = 193
    }

    /**
     * Opens a fresh encrypted store for one peer.
     *
     * The path carries a random suffix so a previous failed run can never leave
     * a database behind that a later run silently reuses — stale state would
     * turn this evidence into a coincidence.
     */
    private fun openPeer(name: String, keyByte: Byte): ArciumCoreWrapper {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val dir = File(context.cacheDir, "arcium-instrumentation/${UUID.randomUUID()}")
        check(dir.mkdirs()) { "could not create a private store directory for $name" }
        return ArciumCoreWrapper().apply {
            openEncryptedDb(File(dir, "$name.db").absolutePath, ByteArray(32) { keyByte })
        }
    }

    /** A peer with an identity saved and prekeys published. */
    private class Peer(val core: ArciumCoreWrapper) {
        val repo = MessageRepository(core)
    }

    private fun peer(name: String, keyByte: Byte, withPrekeys: Boolean = false): Peer {
        val p = Peer(openPeer(name, keyByte))
        p.core.generateAndSaveIdentity() // Ed25519 return value deliberately unused
        if (withPrekeys) p.repo.publishOwnPrekeys()
        return p
    }

    /** Bob's real X25519 DH identity: the first 32 bytes of his exported bundle. */
    private fun x25519IdentityFromBundle(bundle: ByteArray): ByteArray {
        assertTrue(
            "prekey bundle must be $BUNDLE_BYTES_NO_OTP or $BUNDLE_BYTES_WITH_OTP bytes, " +
                "got ${bundle.size}",
            bundle.size == BUNDLE_BYTES_NO_OTP || bundle.size == BUNDLE_BYTES_WITH_OTP,
        )
        return bundle.copyOfRange(0, PUBLIC_KEY_BYTES)
    }

    /** Alice's real X25519 DH identity: the first 32 bytes of the handshake. */
    private fun x25519IdentityFromHandshake(handshake: ByteArray): ByteArray {
        assertEquals(
            "initiator handshake must be identity_pk(32) || ephemeral_pk(32)",
            HANDSHAKE_BYTES,
            handshake.size,
        )
        return handshake.copyOfRange(0, PUBLIC_KEY_BYTES)
    }

    /** Establishes a live Alice↔Bob session and returns both peers and identities. */
    private class LiveSession(
        val alice: Peer,
        val bob: Peer,
        val aliceIdentity: ByteArray,
        val bobIdentity: ByteArray,
    )

    private fun establishAliceAndBob(): LiveSession {
        val bob = peer("bob", 0x11, withPrekeys = true)
        val alice = peer("alice", 0x22)

        val bobBundle = bob.repo.ownPrekeyBundle()
        val bobIdentity = x25519IdentityFromBundle(bobBundle)

        val handshake = alice.repo.startSessionAsInitiator(bobIdentity, bobBundle)
        val aliceIdentity = x25519IdentityFromHandshake(handshake)
        bob.repo.acceptSessionAsResponder(aliceIdentity, handshake)

        return LiveSession(alice, bob, aliceIdentity, bobIdentity)
    }

    /**
     * The core proof. If the native library failed to load, or any layer of the
     * bridge mangled bytes, this cannot pass.
     */
    @Test
    fun twoPeersHandshakeAndExchangeMessagesInBothDirections() {
        val s = establishAliceAndBob()

        val toBob = "hello Bob — through JNA and the real ratchet".toByteArray()
        val ciphertext = s.alice.repo.encryptForPeer(s.bobIdentity, toBob)

        assertTrue("ciphertext must not be empty", ciphertext.isNotEmpty())
        assertNotEquals(
            "ciphertext must not be the plaintext echoed back",
            toBob.toList(),
            ciphertext.toList(),
        )
        assertTrue(
            "ciphertext must be longer than the plaintext (it carries a header)",
            ciphertext.size > toBob.size,
        )

        assertArrayEqualsBytes(
            "Bob must recover Alice's exact plaintext",
            toBob,
            s.bob.repo.decryptFromPeer(s.aliceIdentity, ciphertext),
        )

        // Only now can Bob reply: his sending chain is derived by the receiving
        // ratchet step that Alice's first message just triggered.
        val toAlice = "hello Alice — replying after the ratchet step".toByteArray()
        val reply = s.bob.repo.encryptForPeer(s.aliceIdentity, toAlice)
        assertArrayEqualsBytes(
            "Alice must recover Bob's exact reply",
            toAlice,
            s.alice.repo.decryptFromPeer(s.bobIdentity, reply),
        )
    }

    /**
     * A: naming one peer while handing over another's bundle must be refused —
     * and must leave no session behind, which the NoSession below proves through
     * the real Rust session table rather than by inspecting Kotlin state.
     */
    @Test
    fun mismatchedBundleIdentityIsRejectedAndCreatesNoSession() {
        val bob = peer("bob", 0x31, withPrekeys = true)
        val carol = peer("carol", 0x32, withPrekeys = true)
        val alice = peer("alice", 0x33)

        val bobBundle = bob.repo.ownPrekeyBundle()
        val carolIdentity = x25519IdentityFromBundle(carol.repo.ownPrekeyBundle())

        assertThrows(IllegalStateException::class.java) {
            alice.repo.startSessionAsInitiator(carolIdentity, bobBundle)
        }

        val carolHandle = alice.core.localSessionHandle(carolIdentity)
        assertThrows(
            "the rejected establishment must not have created a session",
            uniffi.arcium_core.CoreException.NoSession::class.java,
        ) { alice.core.encryptMessage(carolHandle, "x".toByteArray()) }
    }

    /** B: an id nobody established must fail as NoSession, never as a fake success. */
    @Test
    fun unknownSessionFailsWithNoSession() {
        val alice = peer("alice", 0x41)
        assertThrows(uniffi.arcium_core.CoreException.NoSession::class.java) {
            alice.core.encryptMessage(918_273_645uL, "x".toByteArray())
        }
    }

    /**
     * C: re-establishing a live session must be refused, and — the part that
     * matters — the original ratchet must still work afterwards. A silent reset
     * would break the message sent at the end.
     */
    @Test
    fun duplicateEstablishmentIsRejectedAndTheOriginalSessionSurvives() {
        val s = establishAliceAndBob()

        // Advance the ratchet so a reset would be observable.
        val first = "first message, advances the ratchet".toByteArray()
        assertArrayEqualsBytes(
            "setup round trip must work before the duplicate attempt",
            first,
            s.bob.repo.decryptFromPeer(
                s.aliceIdentity,
                s.alice.repo.encryptForPeer(s.bobIdentity, first),
            ),
        )

        assertThrows(
            uniffi.arcium_core.CoreException.SessionAlreadyExists::class.java,
        ) { s.alice.repo.startSessionAsInitiator(s.bobIdentity, s.bob.repo.ownPrekeyBundle()) }

        val after = "sent after the rejected duplicate".toByteArray()
        assertArrayEqualsBytes(
            "the surviving session must still decrypt on Bob's side",
            after,
            s.bob.repo.decryptFromPeer(
                s.aliceIdentity,
                s.alice.repo.encryptForPeer(s.bobIdentity, after),
            ),
        )
    }

    /**
     * D: a different peer on an occupied handle must be refused, and Bob's
     * session must survive.
     *
     * This drives the wrapper directly with Bob's handle rather than going
     * through the repository, on purpose: the point is to exercise the Rust
     * collision gate, and Android's derivation is deterministic, so reaching
     * that gate through `handleFor` would require an actual SHA-256 collision.
     */
    @Test
    fun sameHandleForADifferentPeerIsRejectedAndBobSessionSurvives() {
        val s = establishAliceAndBob()
        val carol = peer("carol", 0x52, withPrekeys = true)

        val bobHandle = s.alice.core.localSessionHandle(s.bobIdentity)
        assertThrows(
            uniffi.arcium_core.CoreException.SessionIdCollision::class.java,
        ) { s.alice.core.establishSessionInitiator(bobHandle, carol.repo.ownPrekeyBundle()) }

        val after = "Bob still owns this handle".toByteArray()
        assertArrayEqualsBytes(
            "Bob's session must be untouched by the refused collision",
            after,
            s.bob.repo.decryptFromPeer(
                s.aliceIdentity,
                s.alice.repo.encryptForPeer(s.bobIdentity, after),
            ),
        )
    }

    /** E: the responder path enforces the same binding, and creates nothing. */
    @Test
    fun mismatchedHandshakeIdentityIsRejectedAndCreatesNoSession() {
        val bob = peer("bob", 0x61, withPrekeys = true)
        val carol = peer("carol", 0x62, withPrekeys = true)
        val alice = peer("alice", 0x63)

        val bobBundle = bob.repo.ownPrekeyBundle()
        val handshake = alice.repo.startSessionAsInitiator(
            x25519IdentityFromBundle(bobBundle),
            bobBundle,
        )
        val carolIdentity = x25519IdentityFromBundle(carol.repo.ownPrekeyBundle())

        assertThrows(IllegalStateException::class.java) {
            bob.repo.acceptSessionAsResponder(carolIdentity, handshake)
        }

        val carolHandle = bob.core.localSessionHandle(carolIdentity)
        assertThrows(
            "the rejected responder handshake must not have created a session",
            uniffi.arcium_core.CoreException.NoSession::class.java,
        ) { bob.core.encryptMessage(carolHandle, "x".toByteArray()) }
    }

    /**
     * Byte-array equality with a readable failure. `assertArrayEquals` reports
     * only the first differing index, which is unhelpful when the real failure
     * is "this is still ciphertext".
     */
    private fun assertArrayEqualsBytes(message: String, expected: ByteArray, actual: ByteArray) {
        assertEquals(
            "$message (expected ${expected.size} bytes, got ${actual.size})",
            expected.toList(),
            actual.toList(),
        )
    }
}
