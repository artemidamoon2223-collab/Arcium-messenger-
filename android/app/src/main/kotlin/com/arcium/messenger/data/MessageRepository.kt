package com.arcium.messenger.data

import com.arcium.messenger.ffi.ArciumCoreWrapper
import javax.inject.Inject
import javax.inject.Singleton

data class Message(
    val id: String,
    val sessionId: String,
    val senderKey: ByteArray,
    val ciphertext: ByteArray,
    val timestampMs: Long,
    val isMine: Boolean,
)

@Singleton
class MessageRepository @Inject constructor(
    private val core: ArciumCoreWrapper,
) {
    /** Send an encrypted message to a contact over Tor. */
    suspend fun send(sessionId: String, plaintext: ByteArray): Result<Unit> {
        // TODO: core.ratchetEncrypt(plaintext, sessionId)
        // TODO: transmit via TorManager
        return Result.success(Unit)
    }

    /** Decrypt and store an incoming message. */
    suspend fun receive(sessionId: String, ciphertext: ByteArray): Result<Message> {
        // TODO: core.ratchetDecrypt(ciphertext, sessionId)
        return Result.failure(NotImplementedError("TODO: wire to Rust ratchet"))
    }

    /** Load message history for a session from encrypted storage. */
    fun getHistory(sessionId: String): List<Message> {
        // TODO: read from encrypted SQLite via core-storage
        return emptyList()
    }
}
