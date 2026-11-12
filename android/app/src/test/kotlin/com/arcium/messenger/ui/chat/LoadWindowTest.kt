package com.arcium.messenger.ui.chat

import com.arcium.messenger.ffi.PlaintextText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.arcium_core.ChatEntry
import uniffi.arcium_core.ChatEntryState

/**
 * R-3 (UI): the conversation screen reads the newest entries page by page
 * with `chat_entries_page` instead of the whole history. [loadWindow] against
 * a fake history that answers exactly as the Rust page read does.
 */
class LoadWindowTest {

    private fun entry(seq: ULong) =
        ChatEntry(seq, false, ChatEntryState.RECEIVED, seq, byteArrayOf(), PlaintextText("m$seq"))

    /** A history of [size] entries, seq 1..size, read as `chat_entries_page` does. */
    private class FakeHistory(val size: ULong, val entry: (ULong) -> ChatEntry) {
        val calls = mutableListOf<Pair<ULong?, UInt>>()
        fun page(before: ULong?, limit: UInt): List<ChatEntry> {
            calls += before to limit
            assertTrue("limit $limit", limit in 1u..200u)
            val end = minOf(before?.minus(1uL) ?: size, size)
            if (end == 0uL) return emptyList()
            val start = if (end >= limit.toULong()) end - limit.toULong() + 1uL else 1uL
            return (start..end).map(entry)
        }
    }

    private fun seqs(list: List<ChatEntry>) = list.map { it.seq }

    @Test
    fun theNewestWindowOldestFirst() {
        val h = FakeHistory(137uL, ::entry)
        assertEquals((88uL..137uL).toList(), seqs(loadWindow(PAGE, h::page)))
        assertEquals(listOf<Pair<ULong?, UInt>>(null to 50u), h.calls)
    }

    @Test
    fun aLargerWindowReadsSeveralPagesWithoutGapOrRepeat() {
        val h = FakeHistory(1000uL, ::entry)
        assertEquals((551uL..1000uL).toList(), seqs(loadWindow(450, h::page)))
        assertEquals(listOf<Pair<ULong?, UInt>>(null to 200u, 801uL to 200u, 601uL to 50u), h.calls)
    }

    @Test
    fun aShortHistoryIsReadWhole() {
        for (size in listOf(0uL, 1uL, 49uL, 50uL, 51uL)) {
            val h = FakeHistory(size, ::entry)
            val want = if (size == 0uL) emptyList() else ((if (size > 50uL) size - 49uL else 1uL)..size).toList()
            assertEquals("size $size", want, seqs(loadWindow(PAGE, h::page)))
        }
        val h = FakeHistory(120uL, ::entry)
        assertEquals((1uL..120uL).toList(), seqs(loadWindow(500, h::page)))
        assertTrue("stops at the first entry", h.calls.size <= 2)
    }
}
