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
        // TODO: core.ratchetEncrypt(plaintext, sessionId), transmit via core.startTorTransport()
        return Result.success(Unit)
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
