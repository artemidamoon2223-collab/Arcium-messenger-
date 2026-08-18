package com.arcium.messenger.data

/**
 * Remembers which peer each local session handle belongs to, so a handle
 * collision is refused instead of silently rebinding a session.
 *
 * Handles come from `localSessionHandle`, which truncates a hash of the peer's
 * 32-byte identity public key to 64 bits. Truncation means two distinct peers
 * can in principle produce the same handle — the birthday bound sits near 2^32
 * peers — and the Rust `SessionManager` stores sessions in a map whose insert
 * is an UPSERT with no guard. Without this registry the second peer's handshake
 * would quietly replace the first peer's ratchet, and messages meant for one
 * contact would afterwards be encrypted under the other's session. That is the
 * failure this class exists to make impossible.
 *
 * The full public key is the identity anchor; the handle is only a map key, and
 * that is why the key — not the handle — is what gets compared here.
 *
 * Lifetime is deliberately tied to the Rust sessions it describes: both live in
 * memory for the life of the process (D1), and both are created together in
 * ArciumApp, so the registry cannot outlive or lag behind the session table it
 * is meant to mirror. It is not persisted, because the sessions are not either.
 */
class MessagingSessionRegistry {

    private val peerByHandle = HashMap<ULong, ByteArray>()

    /**
     * Records that [handle] belongs to [peerIdentityPk], and returns the handle.
     *
     * Idempotent for the same peer. Throws IllegalStateException if the handle
     * is already held by a different peer — a truncation collision, which is
     * reported rather than resolved, because picking a winner would silently
     * cost one of the two contacts their session.
     */
    @Synchronized
    fun claim(handle: ULong, peerIdentityPk: ByteArray): ULong {
        val existing = peerByHandle[handle]
        if (existing != null && !existing.contentEquals(peerIdentityPk)) {
            throw IllegalStateException(
                "local session handle $handle is already bound to a different peer " +
                    "(${existing.toHex()}), refusing to rebind it to ${peerIdentityPk.toHex()}. " +
                    "This is a 64-bit truncation collision: the Rust session map would " +
                    "overwrite the existing session rather than keep both.",
            )
        }
        if (existing == null) {
            // Defensive copy: the caller owns its array and may reuse or clear it.
            peerByHandle[handle] = peerIdentityPk.copyOf()
        }
        return handle
    }

    /** The peer a handle is bound to, or null if nothing has claimed it. */
    @Synchronized
    fun peerFor(handle: ULong): ByteArray? = peerByHandle[handle]?.copyOf()

    /** Number of handles currently bound. */
    @Synchronized
    fun size(): Int = peerByHandle.size

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
