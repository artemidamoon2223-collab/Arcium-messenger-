package com.arcium.messenger.messaging

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.arcium.messenger.ffi.ArciumCoreWrapper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.arcium_core.CoreException
import uniffi.arcium_core.NetworkMessenger
import uniffi.arcium_core.SyncReport

/** Where this device stands with the relay, for the UI. */
sealed interface RelayLink {
    /** No relay configured: nothing is sent or fetched. */
    data object NotConfigured : RelayLink

    /** No identity yet: onboarding has not finished. */
    data object NoIdentity : RelayLink

    /**
     * The identity could not be read: an error, not [NoIdentity]. Nothing is
     * sent, fetched or created; the read is retried.
     */
    data class IdentityUnavailable(val reason: String) : RelayLink

    data object Connecting : RelayLink

    /**
     * The last round reached the relay. [problem] is the first other error
     * that round reported (a storage or session error, a refused handshake,
     * a relay refusal), or null if there was none: a round that reached the
     * relay but failed on this device must not read as healthy (R-17).
     */
    data class Online(val atMs: Long, val problem: String? = null) : RelayLink

    /** The last round did not reach the relay; [networkAvailable] is Android's view. */
    data class Offline(val reason: String, val networkAvailable: Boolean) : RelayLink
}

/** How `CoreError::Network` is rendered in a sync report. */
internal const val NETWORK_ERROR = "network:"

/**
 * The start of the line a round adds when its time budget ran out
 * (`BUDGET_EXHAUSTED` in crates/mobile-ffi/src/network.rs). It is not an
 * error: the next round continues (docs/NET-MESSAGING.md, section 7).
 */
internal const val BUDGET_NOTICE = "round budget exhausted"

/**
 * Where this device stands after a round that produced [report]. A network
 * error means the relay was not reached ([RelayLink.Offline]); any other
 * error, except the budget notice, is kept as [RelayLink.Online.problem].
 */
internal fun linkAfterRound(report: SyncReport, nowMs: Long, networkAvailable: () -> Boolean): RelayLink {
    val networkError = report.errors.firstOrNull { it.startsWith(NETWORK_ERROR) }
    return if (networkError == null) {
        RelayLink.Online(
            atMs = nowMs,
            problem = report.errors.firstOrNull { !it.startsWith(BUDGET_NOTICE) },
        )
    } else {
        RelayLink.Offline(reason = networkError, networkAvailable = networkAvailable())
    }
}

/**
 * The one [NetworkMessenger] of this process and the loop that syncs it.
 *
 * All messaging state lives in Rust (docs/NET-MESSAGING.md, sections 5 and
 * 10): this class only decides *when* `syncConversations` runs, and tells the
 * UI when to read again ([revision]). It keeps no message, session or
 * delivery state of its own.
 *
 * Sync runs only while the app is visible ([syncWhileVisible], driven by the
 * activity's lifecycle): after a round in which something arrived, again after
 * [ACTIVE_DELAY_MS], otherwise after [IDLE_DELAY_MS], backing off to
 * [MAX_BACKOFF_MS] while the relay is unreachable, and at once when the user
 * sends or Android reports a network. Nothing runs while the app is in the
 * background: messages wait on the relay until it is opened again.
 */
class MessengerService(
    context: Context,
    private val core: ArciumCoreWrapper,
    val relay: RelaySettings,
) {
    private val connectivity = checkNotNull(context.getSystemService(ConnectivityManager::class.java))

    private val _link = MutableStateFlow<RelayLink>(RelayLink.NotConfigured)
    val link: StateFlow<RelayLink> = _link

    private val _revision = MutableStateFlow(0L)

    /** Changes whenever stored conversation state may have changed. */
    val revision: StateFlow<Long> = _revision

    private val wake = Channel<Unit>(Channel.CONFLATED)

    /** Rust calls may block on the store or the network: one thread for sync. */
    @OptIn(ExperimentalCoroutinesApi::class)
    private val syncDispatcher = Dispatchers.IO.limitedParallelism(1)

    private var messenger: NetworkMessenger? = null
    private var messengerRelay: String? = null

    /**
     * The messenger for the configured relay. Local calls (history, contacts,
     * queuing a text) work without one being reachable; with no relay
     * configured the address is empty and only network calls fail.
     */
    @Synchronized
    fun messenger(): NetworkMessenger {
        val address = relay.address.value.orEmpty()
        val current = messenger
        if (current != null && messengerRelay == address) return current
        // A new relay starts a new messenger: its in-memory retransmission
        // clock restarts, so everything pending is sent once more.
        return core.networkMessenger(address).also {
            messenger = it
            messengerRelay = address
            current?.close()
        }
    }

    /** Runs [block] against the messenger off the main thread. */
    suspend fun <T> call(block: (NetworkMessenger) -> T): T =
        withContext(Dispatchers.IO) { block(messenger()) }

    /**
     * Runs [block] against the messenger on the sync thread, so it never
     * overlaps a sync round. For deleting a contact: a round in flight could
     * otherwise write that contact's records (its flags, its history) again
     * after they were deleted.
     */
    suspend fun <T> callBetweenRounds(block: (NetworkMessenger) -> T): T =
        withContext(syncDispatcher) { block(messenger()) }

    /** Local state changed (a text queued, a contact added): read again and sync soon. */
    fun changed() {
        _revision.value++
        wake.trySend(Unit)
    }

    /**
     * Syncs until cancelled. Call from a lifecycle-bound coroutine that runs
     * only while the app is visible.
     */
    suspend fun syncWhileVisible() {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                wake.trySend(Unit)
            }

            override fun onLost(network: Network) {
                wake.trySend(Unit)
            }
        }
        connectivity.registerDefaultNetworkCallback(callback)
        try {
            var backoff = ACTIVE_DELAY_MS
            while (true) {
                val delayMs = round()?.let { report ->
                    if (report.reachedRelay()) {
                        backoff = ACTIVE_DELAY_MS
                        if (report.busy()) ACTIVE_DELAY_MS else IDLE_DELAY_MS
                    } else {
                        backoff = (backoff * 2).coerceAtMost(MAX_BACKOFF_MS)
                        backoff
                    }
                } ?: if (_link.value is RelayLink.IdentityUnavailable) MAX_BACKOFF_MS else Long.MAX_VALUE
                withTimeoutOrNull(delayMs) { wake.receive() }
            }
        } finally {
            connectivity.unregisterNetworkCallback(callback)
        }
    }

    /** One sync round; null if none can run (no relay, no identity, identity unreadable). */
    private suspend fun round(): SyncReport? {
        if (relay.address.value == null) {
            _link.value = RelayLink.NotConfigured
            return null
        }
        val hasIdentity = try {
            withContext(syncDispatcher) { core.loadIdentityPublicKey() != null }
        } catch (e: CoreException) {
            // Caught here so the loop keeps running; it never creates one.
            _link.value = RelayLink.IdentityUnavailable(e.message.orEmpty())
            return null
        }
        if (!hasIdentity) {
            _link.value = RelayLink.NoIdentity
            return null
        }
        val report = withContext(syncDispatcher) {
            if (_link.value !is RelayLink.Online) _link.value = RelayLink.Connecting
            messenger().syncConversations()
        }
        _link.value = linkAfterRound(report, System.currentTimeMillis()) { networkAvailable() }
        _revision.value++
        return report
    }

    private fun networkAvailable(): Boolean {
        val caps = connectivity.getNetworkCapabilities(connectivity.activeNetwork) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    private fun SyncReport.reachedRelay() = errors.none { it.startsWith(NETWORK_ERROR) }

    /**
     * Something arrived this round, so more may follow soon (receipts,
     * replies). Retransmissions alone do not count: waiting for an offline
     * contact must not keep the fast pace.
     */
    private fun SyncReport.busy() = accepted > 0u || delivered > 0u || sessionsAccepted > 0u

    private companion object {
        const val ACTIVE_DELAY_MS = 1_500L
        const val IDLE_DELAY_MS = 4_000L
        const val MAX_BACKOFF_MS = 30_000L
    }
}
