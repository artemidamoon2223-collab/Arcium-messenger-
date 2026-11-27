package com.arcium.messenger.ui.settings

import uniffi.arcium_core.TorState

/**
 * What Settings says about how the app reaches the configured relay
 * (docs/NET-MESSAGING.md, section 3a): through the Tor client built into the
 * app when [throughTor] (`relayGoesThroughTor`), then with Tor's state once
 * it has been read ([tor] not null), else directly. Over Tor the relay never
 * sees this device's IP address: if Tor cannot be had, nothing is sent (the
 * core never tries such a relay directly).
 */
internal fun routeStatus(throughTor: Boolean, tor: TorState?): String = when {
    !throughTor -> WITHOUT_TOR
    tor == null -> THROUGH_TOR
    else -> "$THROUGH_TOR ${torStatus(tor)}"
}

internal const val WITHOUT_TOR = "Without Tor: the relay sees your IP address."
internal const val THROUGH_TOR = "Through Tor: the relay does not see your IP address."

/** What Settings says about the process's Tor client in [state] (`tor_state()`). */
internal fun torStatus(state: TorState): String = when (state) {
    TorState.NOT_STARTED -> "Tor starts with the first connection to the relay."
    TorState.STARTING -> "Tor is starting; a start can take up to two minutes."
    TorState.RUNNING -> "Tor is running."
    TorState.NEEDS_UPDATE ->
        "Tor needs an app update: the Tor network requires a newer version of this app. " +
            "Until it is updated, nothing reaches this relay."
    TorState.FAILED -> "Tor did not start. The app tries again at its next sync, at least a minute later."
}
