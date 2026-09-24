package com.arcium.messenger.debug

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.os.Process
import com.arcium.messenger.ffi.ArciumCoreWrapper
import java.io.File

/**
 * Debug-only harness for the S2-B2 process-death tests
 * (`DurableMessagingInstrumentationTest`). It runs in its own process
 * (`:victim`), performs exactly one durable messaging operation on the store
 * the caller names, writes what that operation returned to files, and then
 * kills its own process with `Process.killProcess` (SIGKILL): no finally
 * blocks, no finalizers, no store close, no acknowledgement.
 *
 * A provider rather than a service: the caller reaches it through an unstable
 * client, so this process dying does not take the caller down with it, and
 * nothing restarts it and replays the operation.
 *
 * Files in the directory named by `dir`:
 * - inputs: `plaintext`, `wire`, `handshake` (as the scenario needs);
 * - outputs: `published` (send), `received` (receive), then `done`, or
 *   `error` with the exception if the operation failed.
 */
class CrashVictimProvider : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        require(method == METHOD_RUN) { "unknown method $method" }
        val args = requireNotNull(extras)
        val dir = File(requireNotNull(args.getString(KEY_DIR)))
        val core = ArciumCoreWrapper()
        try {
            core.openEncryptedDb(
                requireNotNull(args.getString(KEY_DB)),
                ByteArray(32) { args.getByte(KEY_MASTER_BYTE) },
            )
            val session = args.getLong(KEY_SESSION).toULong()
            when (arg) {
                SCENARIO_SEND -> {
                    val sent = core.sendMessage(session, File(dir, "plaintext").readBytes())
                    // Handed to the transport: the caller now holds these bytes.
                    File(dir, "published").writeBytes(sent.wire)
                }
                SCENARIO_RECEIVE -> {
                    when (val r = core.receiveMessage(session, File(dir, "wire").readBytes())) {
                        is uniffi.arcium_core.ReceiveResult.Accepted ->
                            File(dir, "received").writeBytes(r.message.plaintext)
                        is uniffi.arcium_core.ReceiveResult.Duplicate ->
                            error("unexpected duplicate")
                    }
                }
                SCENARIO_RESPOND ->
                    core.establishSessionResponder(session, File(dir, "handshake").readBytes())
                else -> error("unknown scenario $arg")
            }
            File(dir, "done").writeText("ok")
        } catch (t: Throwable) {
            File(dir, "error").writeText(t.toString())
        }
        // Die before returning, acknowledging or closing anything.
        Process.killProcess(Process.myPid())
        return null
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    companion object {
        const val AUTHORITY = "com.arcium.messenger.debug.victim"
        const val PROCESS_SUFFIX = ":victim"
        const val METHOD_RUN = "run"
        const val SCENARIO_SEND = "send"
        const val SCENARIO_RECEIVE = "receive"
        const val SCENARIO_RESPOND = "respond"
        const val KEY_DIR = "dir"
        const val KEY_DB = "db"
        const val KEY_MASTER_BYTE = "masterByte"
        const val KEY_SESSION = "session"
    }
}
