package com.arcium.messenger.messaging

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ContactCardTextTest {

    private val card = ByteArray(65) { it.toByte() }

    @Test
    fun aCardSurvivesTheRoundTripAndWrappingInTransit() {
        val text = ContactCardText.encode(card)
        assertEquals(ContactCardText.PREFIX.length + 130, text.length)
        assertArrayEquals(card, ContactCardText.decode(text))
        val wrapped = "  " + text.chunked(20).joinToString("\n") + " \n"
        assertArrayEquals(card, ContactCardText.decode(wrapped))
        assertArrayEquals(card, ContactCardText.decode(text.uppercase()))
    }

    @Test
    fun anythingElseIsRefused() {
        val text = ContactCardText.encode(card)
        assertNull(ContactCardText.decode(""))
        assertNull(ContactCardText.decode(text.removePrefix(ContactCardText.PREFIX)))
        assertNull(ContactCardText.decode(text.dropLast(2)))
        assertNull(ContactCardText.decode(text + "00"))
        assertNull(ContactCardText.decode(text.dropLast(1) + "g"))
    }
}
