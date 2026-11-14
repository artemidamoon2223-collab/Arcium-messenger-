package com.arcium.messenger.messaging

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.arcium.messenger.ArciumApp
import com.arcium.messenger.MainActivity
import com.arcium.messenger.startup.StartupState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch

/**
 * Background receive: runs the app's sync loop
 * ([MessengerService.syncInBackground]) while the app is not visible, as a
 * foreground service of type dataSync with an ongoing notice. No push service
 * and no server of its own: it is the same loop, talking to the same relay.
 *
 * Opt-in ([BackgroundSettings], off by default). Only the visible app starts
 * it ([BackgroundReceive.startWhileAllowed]), and it stops itself once
 * [backgroundState] is no longer RUN: the user turned it off or removed the
 * relay. `START_NOT_STICKY`: once its process ends, nothing runs until the app
 * is opened again, and nothing starts it after a reboot.
 */
class BackgroundReceiveService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /** [syncWhileAllowed], while it is active. Touched on the main thread only. */
    private var job: Job? = null

    /** The newest start request seen, so stopping never drops a later one. */
    private var lastStartId = 0

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        BackgroundReceive.createChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        // First, whatever follows: a service started with
        // startForegroundService must call startForeground promptly, also when
        // it stops again at once.
        val notice = BackgroundReceive.connectionNotice(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(BackgroundReceive.CONNECTION_ID, notice, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(BackgroundReceive.CONNECTION_ID, notice)
        }
        if (job?.isActive != true) job = scope.launch { syncWhileAllowed() }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        // Ends the loop; a round already running on the sync thread finishes
        // first, and the visible app's loop waits for it.
        scope.cancel()
        super.onDestroy()
    }

    /** Syncs while [backgroundState] is RUN, then stops the service. */
    private suspend fun syncWhileAllowed() {
        // As MainActivity does: nothing before start-up is Ready, because the
        // messenger does not exist before that. A blocked start-up needs the
        // app's own screen to retry, so the service stops.
        val startup = ArciumApp.startup.state.first { it != StartupState.Checking }
        if (startup == StartupState.Ready) {
            val messenger = ArciumApp.messenger
            // Notifications can be turned off in system settings while this
            // runs, and below Android 13 that does not end the process: they
            // are checked again on every tick, not only at start.
            val ticks = flow {
                while (true) {
                    emit(Unit)
                    delay(NOTIFICATION_CHECK_MS)
                }
            }
            val states = combine(messenger.background.enabled, messenger.relay.address, ticks) { enabled, relay, _ ->
                backgroundState(enabled, startup, relay, BackgroundReceive.notificationsAllowed(this))
            }
            if (states.first() == BackgroundState.RUN) {
                val loop = scope.launch {
                    messenger.syncInBackground { BackgroundReceive.notifyNewMessage(this@BackgroundReceiveService) }
                }
                try {
                    states.first { it != BackgroundState.RUN }
                } finally {
                    loop.cancel()
                }
            }
        }
        stopSelf(lastStartId)
    }

    private companion object {
        const val NOTIFICATION_CHECK_MS = 30_000L
    }
}

/** Starting [BackgroundReceiveService], and the notifications it shows. */
object BackgroundReceive {

    internal const val CONNECTION_ID = 1
    private const val MESSAGE_ID = 2
    private const val CONNECTION_CHANNEL = "background_connection"
    private const val MESSAGE_CHANNEL = "new_messages"

    /**
     * Until cancelled, starts [BackgroundReceiveService] at once and whenever
     * the switch or the relay changes, if [backgroundState] is RUN. Call while
     * the app is visible and start-up is Ready: Android lets an app start a
     * foreground service from the foreground. Starting it again while it runs
     * changes nothing; it stops itself.
     */
    suspend fun startWhileAllowed(context: Context, messenger: MessengerService) {
        combine(messenger.background.enabled, messenger.relay.address) { enabled, relay ->
            backgroundState(enabled, ArciumApp.startup.state.value, relay, notificationsAllowed(context))
        }.collect { state ->
            if (state == BackgroundState.RUN) {
                context.startForegroundService(Intent(context, BackgroundReceiveService::class.java))
            }
        }
    }

    /** On Android 13 and later: the user has not granted POST_NOTIFICATIONS yet. */
    fun mustAskForNotifications(context: Context): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED

    /** Android shows this app's notifications. */
    fun notificationsAllowed(context: Context): Boolean =
        !mustAskForNotifications(context) && NotificationManagerCompat.from(context).areNotificationsEnabled()

    /** Removes the "new message" notification, for when the app is opened. */
    fun clearNewMessage(context: Context) {
        manager(context).cancel(MESSAGE_ID)
    }

    internal fun createChannels(context: Context) {
        val connection = NotificationChannel(
            CONNECTION_CHANNEL,
            "Background connection",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Shown while the app stays connected to the relay in the background."
            lockscreenVisibility = Notification.VISIBILITY_SECRET
        }
        val messages = NotificationChannel(
            MESSAGE_CHANNEL,
            "New messages",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Says that a message arrived, without the sender or the text."
            lockscreenVisibility = Notification.VISIBILITY_SECRET
        }
        manager(context).createNotificationChannels(listOf(connection, messages))
    }

    /** The ongoing notice of the foreground service. */
    internal fun connectionNotice(context: Context): Notification {
        val text = "Arcium Messenger stays connected to the relay while it is closed, to receive " +
            "messages. Turn this off in Settings."
        return NotificationCompat.Builder(context, CONNECTION_CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle("Connected in the background")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setShowWhen(false)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(openApp(context))
            .build()
    }

    /**
     * "New message": no sender, no text, nothing that tells contacts apart,
     * and not shown on the lock screen at all (secret: the lock screen would
     * otherwise still show the app's name). Tapping it opens the app.
     */
    internal fun notifyNewMessage(context: Context) {
        if (!notificationsAllowed(context)) return
        val notification = NotificationCompat.Builder(context, MESSAGE_CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle("New message")
            .setContentText("Open the app to read it.")
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(openApp(context))
            .setAutoCancel(true)
            .build()
        manager(context).notify(MESSAGE_ID, notification)
    }

    /** Brings the app's task to the front, as the launcher does. */
    private fun openApp(context: Context): PendingIntent {
        val intent = Intent(context, MainActivity::class.java)
            .setAction(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE)
    }

    private fun manager(context: Context): NotificationManager =
        checkNotNull(context.getSystemService(NotificationManager::class.java))
}
