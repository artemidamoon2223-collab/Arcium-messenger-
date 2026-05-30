package com.arcium.messenger.network

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Manages the Tor (arti) connection for anonymous routing.
 * The Rust crate `core-transport` wraps arti. At build time, expose it via
 * UniFFI so this class can call into the Rust Tor implementation.
 */
@Singleton
class TorManager @Inject constructor() {

    private var isRunning = false

    fun start() {
        // TODO: call into core-transport (Rust arti wrapper) via UniFFI
        // TODO: block until bootstrap completes (~10s on first run)
        isRunning = true
    }

    fun stop() {
        // TODO: shut down the Tor circuit
        isRunning = false
    }

    fun isReady(): Boolean = isRunning

    /** Send bytes to a hidden service (.onion address) over Tor. */
    suspend fun sendOnion(address: String, data: ByteArray): Result<ByteArray> {
        // TODO: open TorStream to address, write data, read response
        return Result.failure(NotImplementedError("TODO: wire to arti via UniFFI"))
    }
}
