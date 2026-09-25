package com.arcium.messenger.ffi

import android.app.ActivityManager
import android.content.Context
import android.os.Bundle
import android.os.RemoteException
import android.os.SystemClock
import com.arcium.messenger.debug.CrashVictimProvider
import java.io.File

private const val VICTIM_TIMEOUT_MS = 30_000L

/**
 * Runs [scenario] in the `:victim` process (`CrashVictimProvider`, debug
 * builds only) and waits for that process to be gone. Fails if the victim
 * reported an error or died before finishing its operation.
 */
internal fun runInVictimProcess(
    context: Context,
    dir: File,
    scenario: String,
    db: String,
    key: Byte,
    session: ULong,
) {
    val extras = Bundle().apply {
        putString(CrashVictimProvider.KEY_DIR, dir.absolutePath)
        putString(CrashVictimProvider.KEY_DB, db)
        putByte(CrashVictimProvider.KEY_MASTER_BYTE, key)
        putLong(CrashVictimProvider.KEY_SESSION, session.toLong())
    }
    val client = checkNotNull(
        context.contentResolver.acquireUnstableContentProviderClient(CrashVictimProvider.AUTHORITY),
    ) { "victim provider not found — is this a debug build?" }
    try {
        client.call(CrashVictimProvider.METHOD_RUN, scenario, extras)
        throw AssertionError("the victim returned instead of dying")
    } catch (expected: RemoteException) {
        // The victim process died during the call, as intended
        // (DeadObjectException). Checked below: it finished its operation
        // and is gone.
    } finally {
        client.close()
    }
    val victim = context.packageName + CrashVictimProvider.PROCESS_SUFFIX
    val am = context.getSystemService(ActivityManager::class.java)
    val deadline = SystemClock.elapsedRealtime() + VICTIM_TIMEOUT_MS
    while (am.runningAppProcesses.orEmpty().any { it.processName == victim }) {
        check(SystemClock.elapsedRealtime() < deadline) { "victim process still alive" }
        SystemClock.sleep(50)
    }
    val error = File(dir, "error")
    check(!error.exists()) { "victim failed: ${error.readText()}" }
    check(File(dir, "done").exists()) { "victim died before finishing its operation" }
}
