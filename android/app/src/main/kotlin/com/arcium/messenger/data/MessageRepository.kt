package com.arcium.messenger.data

import com.arcium.messenger.ffi.ArciumCoreWrapper

data class Message(
    val id: String,
    val sessionId: String,
    val senderKey: ByteArray,
    val ciphertext: ByteArray,
    val timestampMs: Long,
    val isMine: Boolean,
)

class MessageRepository(private val core: ArciumCoreWrapper = ArciumCoreWrapper()) {

    suspend fun send(sessionId: String, plaintext: ByteArray): Result<Unit> {
        // Honesty fix: no ratchet/transport path exists yet, so no outbound
        // message operation actually happens. Do not report success for a no-op.
        // TODO: wire to Rust ratchet + transport once those are bridged.
        return Result.failure(NotImplementedError("Message delivery is not connected yet."))
    }

    suspend fun receive(sessionId: String, ciphertext: ByteArray): Result<Message> {
        // TODO: core.ratchetDecrypt(ciphertext, sessionId)
        return Result.failure(NotImplementedError("TODO: wire to Rust ratchet"))
    }

    fun getHistory(sessionId: String): List<Message> {
        // TODO: read from encrypted SQLite via core-storage
        return emptyList()
    }
}
