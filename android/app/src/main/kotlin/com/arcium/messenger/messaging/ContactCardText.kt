package com.arcium.messenger.messaging

/**
 * The text form of a `CONTACT_CARD_V1` that users pass to each other out of
 * band (copy and paste, the share sheet, another messenger):
 * `ARCIUM-CARD-1:` followed by the 65 card bytes in hex.
 *
 * This is only a transport encoding. It proves nothing about who sent it: the
 * two users confirm the card by comparing its fingerprint, which each device
 * computes from the card bytes (`contactCardFingerprint`), before it is pinned.
 */
object ContactCardText {
    const val PREFIX = "ARCIUM-CARD-1:"
    private const val CARD_BYTES = 65

    fun encode(card: ByteArray): String {
        require(card.size == CARD_BYTES) { "a contact card is $CARD_BYTES bytes" }
        return PREFIX + card.joinToString("") { "%02x".format(it) }
    }

    /**
     * The card bytes in [text], or null if it is not a card. Whitespace and
     * line breaks are ignored, so a card that was wrapped in transit still
     * parses; anything else is refused rather than guessed at.
     */
    fun decode(text: String): ByteArray? {
        val compact = text.filterNot { it.isWhitespace() }
        if (!compact.startsWith(PREFIX, ignoreCase = true)) return null
        val hex = compact.substring(PREFIX.length)
        if (hex.length != CARD_BYTES * 2) return null
        if (hex.any { Character.digit(it, 16) < 0 }) return null
        return ByteArray(CARD_BYTES) { i ->
            ((Character.digit(hex[2 * i], 16) shl 4) or Character.digit(hex[2 * i + 1], 16)).toByte()
        }
    }
}
