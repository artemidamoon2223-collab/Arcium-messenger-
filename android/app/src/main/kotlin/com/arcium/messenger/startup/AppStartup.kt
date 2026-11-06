package com.arcium.messenger.startup

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Why startup is blocked. The text carries no key material. */
sealed interface StartupProblem {
    /** The store exists but its master key does not. */
    data object KeyMissingForExistingData : StartupProblem

    /** The master key exists but cannot be used, or none could be stored. */
    data class KeyUnavailable(val reason: String) : StartupProblem

    /** The key is available but the store did not open. */
    data class StoreUnavailable(val reason: String) : StartupProblem
}

sealed interface StartupState {
    /** A check is running (the first one, or a retry). */
    data object Checking : StartupState

    /** The store is open; the app's core and messenger exist. */
    data object Ready : StartupState

    /** Nothing was opened or created. Only [AppStartup.retry] can change this. */
    data class Blocked(val problem: StartupProblem) : StartupState
}

/**
 * Runs the app's start-up check at most once at a time, and stops running it
 * once it has succeeded.
 *
 * [check] opens the store and builds whatever depends on it, or reports why it
 * cannot. It must create nothing when it reports a problem; it is called again
 * only after a [StartupState.Blocked] result. Calls to [start] and [retry] are
 * serialized: a retry that arrives while another check runs waits for it, and
 * after a [StartupState.Ready] result every later call returns at once without
 * calling [check] again, so initialization happens once.
 */
class AppStartup(private val check: () -> StartupState) {

    private val lock = Any()
    private val _state = MutableStateFlow<StartupState>(StartupState.Checking)
    val state: StateFlow<StartupState> = _state

    /** Runs the first check. Same as [retry]; named for the call site. */
    fun start(): StartupState = retry()

    /** Runs the check again unless start-up already succeeded. Blocking. */
    fun retry(): StartupState = synchronized(lock) {
        val current = _state.value
        if (current == StartupState.Ready) return current
        _state.value = StartupState.Checking
        val outcome = try {
            check()
        } catch (e: Exception) {
            // A check is meant to report problems, not throw them; anything it
            // throws still blocks rather than crashing the caller.
            StartupState.Blocked(StartupProblem.StoreUnavailable("start-up failed (${e.javaClass.simpleName})"))
        }
        // A check that ends without an outcome is treated as a failure.
        val next = if (outcome == StartupState.Checking) {
            StartupState.Blocked(StartupProblem.StoreUnavailable("start-up check did not finish"))
        } else {
            outcome
        }
        _state.value = next
        next
    }
}
