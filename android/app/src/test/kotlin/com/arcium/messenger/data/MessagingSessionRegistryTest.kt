package com.arcium.messenger.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Covers the guard that makes a 64-bit truncated session handle safe to use:
 * a handle may only ever belong to one peer, and the peer is compared by its
 * full 32-byte identity key rather than by the handle.
 *
 * Pure JVM logic — the registry touches no FFI, so this runs without a device.
 */
class MessagingSessionRegistryTest {

    private fun key(byte: Byte) = ByteArray(32) { byte }

    @Test
    fun `first claim binds the handle and returns it`() {
        val registry = MessagingSessionRegistry()
        val alice = key(1)

        assertEquals(42uL, registry.claim(42uL, alice))
        assertEquals(1, registry.size())
        assertTrue(registry.peerFor(42uL)!!.contentEquals(alice))
    }

    @Test
    fun `claiming the same handle for the same peer is idempotent`() {
        val registry = MessagingSessionRegistry()
        val alice = key(1)

        registry.claim(42uL, alice)
        registry.claim(42uL, alice)
        registry.claim(42uL, key(1)) // equal content, different array instance

        assertEquals(1, registry.size())
        assertTrue(registry.peerFor(42uL)!!.contentEquals(alice))
    }

    /**
     * The collision this class exists for: two distinct peers whose handles
     * happen to coincide. The second must be refused, because Rust's session
     * map would otherwise overwrite the first peer's ratchet silently.
     */
    @Test
    fun `claiming a bound handle for a different peer throws and keeps the first binding`() {
        val registry = MessagingSessionRegistry()
        val alice = key(1)
        val bob = key(2)
        registry.claim(42uL, alice)

        val error = assertThrows(IllegalStateException::class.java) {
            registry.claim(42uL, bob)
        }

        assertTrue(
            "message should name the handle, got: ${error.message}",
            error.message!!.contains("42"),
        )
        assertEquals("the rejected claim must not have been stored", 1, registry.size())
        assertTrue(
            "the original binding must survive the rejected claim",
            registry.peerFor(42uL)!!.contentEquals(alice),
        )
    }

    @Test
    fun `mutating the caller's array after claim does not change the stored identity`() {
        val registry = MessagingSessionRegistry()
        val alice = key(1)
        registry.claim(42uL, alice)

        alice.fill(9) // caller reuses or scrubs its buffer

        assertTrue(
            "the registry must hold its own copy",
            registry.peerFor(42uL)!!.contentEquals(key(1)),
        )
    }

    @Test
    fun `peerFor returns a defensive copy that cannot corrupt the binding`() {
        val registry = MessagingSessionRegistry()
        registry.claim(42uL, key(1))

        val first = registry.peerFor(42uL)!!
        first.fill(9)

        val second = registry.peerFor(42uL)!!
        assertNotSame(first, second)
        assertTrue("a mutated read must not affect the store", second.contentEquals(key(1)))
    }

    @Test
    fun `different handles coexist independently`() {
        val registry = MessagingSessionRegistry()
        val alice = key(1)
        val bob = key(2)

        registry.claim(42uL, alice)
        registry.claim(77uL, bob)

        assertEquals(2, registry.size())
        assertTrue(registry.peerFor(42uL)!!.contentEquals(alice))
        assertTrue(registry.peerFor(77uL)!!.contentEquals(bob))
    }

    @Test
    fun `an unclaimed handle resolves to nothing`() {
        assertNull(MessagingSessionRegistry().peerFor(42uL))
    }
}
