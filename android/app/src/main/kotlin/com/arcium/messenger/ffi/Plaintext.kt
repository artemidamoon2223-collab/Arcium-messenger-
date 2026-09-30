package com.arcium.messenger.ffi

/**
 * Message plaintext in the UniFFI-generated records (`IncomingMessage.plaintext`,
 * `ReceivedText.text`, `ChatEntry.text`). The generated code uses these types
 * because `crates/mobile-ffi/uniffi.toml` maps the Rust custom types of the same
 * names to them.
 *
 * `toString` is `"<redacted>"`, so formatting a record that holds one — its own
 * `toString`, string interpolation, a log line, an assertion message — does not
 * print the message. Equality and hashing are those of the wrapped value, as
 * they were before. This covers accidental formatting only: [bytes] and
 * [value] are the plaintext, and nothing here wipes or hides them from code
 * that reads them.
 */
@JvmInline
value class PlaintextBytes(val bytes: ByteArray) {
    override fun toString(): String = REDACTED
}

/** See [PlaintextBytes]. */
@JvmInline
value class PlaintextText(val value: String) {
    override fun toString(): String = REDACTED
}

private const val REDACTED = "<redacted>"
