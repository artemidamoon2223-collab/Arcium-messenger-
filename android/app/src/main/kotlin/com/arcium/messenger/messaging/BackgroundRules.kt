package com.arcium.messenger.messaging

import com.arcium.messenger.startup.StartupState
import com.arcium.messenger.ui.toHex
import uniffi.arcium_core.Conversation

/** Whether the background-receive service may run, and if not, why. */
internal enum class BackgroundState {
    /** The user has not turned it on. */
    OFF,

    /** Start-up is still checking: the messenger does not exist yet. */
    WAITING_FOR_STARTUP,

    /** Start-up is blocked: there is no store to sync. */
    STARTUP_BLOCKED,

    /** No relay is configured: there is nothing to stay connected to. */
    NO_RELAY,

    /**
     * Android may not show this app's notifications, so the service would
     * run without its notice and could not report a new message.
     */
    NOTIFICATIONS_BLOCKED,

    RUN,
}

/**
 * Whether the background-receive service may run: the user turned it on
 * ([enabled]), start-up is Ready, a relay is configured ([relayAddress]),
 * and Android allows the app's notifications.
 */
internal fun backgroundState(
    enabled: Boolean,
    startup: StartupState,
    relayAddress: String?,
    notificationsAllowed: Boolean,
): BackgroundState = when {
    !enabled -> BackgroundState.OFF
    startup is StartupState.Blocked -> BackgroundState.STARTUP_BLOCKED
    startup != StartupState.Ready -> BackgroundState.WAITING_FOR_STARTUP
    relayAddress == null -> BackgroundState.NO_RELAY
    !notificationsAllowed -> BackgroundState.NOTIFICATIONS_BLOCKED
    else -> BackgroundState.RUN
}

/** Wait after a round that changed nothing, while the app is on screen. */
internal const val VISIBLE_IDLE_DELAY_MS = 4_000L

/**
 * Wait after a round that changed nothing, while only the background service
 * runs the loop. Each round is a new connection that publishes the bundle and
 * scans the mailbox, so the background pace is kept low: battery, data, and
 * how often the device shows itself to the relay and the network.
 */
internal const val BACKGROUND_IDLE_DELAY_MS = 30_000L

/** The wait after a round that changed nothing ([VISIBLE_IDLE_DELAY_MS] or [BACKGROUND_IDLE_DELAY_MS]). */
internal fun idleDelayMs(visible: Boolean): Long =
    if (visible) VISIBLE_IDLE_DELAY_MS else BACKGROUND_IDLE_DELAY_MS

/** The newest entry of one conversation: its number, and whether the contact wrote it. */
internal data class NewestEntry(val seq: ULong, val incoming: Boolean)

/**
 * The newest entry of each conversation, by the contact's X25519 key in hex.
 * A conversation without entries is left out. Keeps no name and no text.
 */
internal fun newestEntries(conversations: List<Conversation>): Map<String, NewestEntry> =
    conversations.mapNotNull { c -> c.last?.let { c.peer.toHex() to NewestEntry(it.seq, !it.outgoing) } }.toMap()

/**
 * Whether to show a "new message" notification after a round: the app is not
 * [visible], and some conversation's newest entry in [after] is a text from
 * the contact and not the newest entry it had [before] the round.
 *
 * Entries take the next number as they are recorded and are never removed,
 * except all at once when the contact is deleted (docs/NET-MESSAGING.md,
 * section 10). So a newest entry with another number is one recorded since
 * [before], also in a history that restarted at 1. The unread count is not
 * used: it says what the user has not seen, not what arrived in this round.
 * Null on either side means that list could not be read; nothing is shown
 * then.
 */
internal fun notifyAfterRound(
    before: Map<String, NewestEntry>?,
    after: Map<String, NewestEntry>?,
    visible: Boolean,
): Boolean {
    if (visible || before == null || after == null) return false
    return after.any { (peer, newest) -> newest.incoming && newest.seq != before[peer]?.seq }
}
