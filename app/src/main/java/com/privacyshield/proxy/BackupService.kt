package com.privacyshield.proxy

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.privacyshield.proxy.core.CloudSync
import java.util.concurrent.atomic.AtomicBoolean

/** Foreground, wake-locked encrypted backup/restore execution. */
class BackupService : Service() {
    private val running = AtomicBoolean(false)
    @Volatile private var worker: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_CANCEL) {
            worker?.interrupt()
            return START_NOT_STICKY
        }
        val operation = intent?.action ?: return START_NOT_STICKY
        if (operation !in setOf(ACTION_BACKUP, ACTION_RESTORE, ACTION_RESTORE_FROM) || !running.compareAndSet(false, true)) {
            return START_NOT_STICKY
        }
        val snapshot = intent.getStringExtra(EXTRA_SNAPSHOT)
        createChannel()
        val label = if (operation == ACTION_BACKUP) "Preparing encrypted backup" else "Preparing encrypted restore"
        startForeground(NOTIFICATION_ID, notification(label, 0L, true).build())
        saveState(operation, "running", label, 0L)
        worker = Thread {
            val lock = (getSystemService(POWER_SERVICE) as PowerManager)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "$packageName:backup")
            lock.acquire(6 * 60 * 60 * 1000L)
            try {
                if (operation == ACTION_BACKUP) {
                    CloudSync.push(this)
                    finishJob(operation, true, "Encrypted Google Drive backup completed")
                } else {
                    stopService(Intent(this, ShieldVpnService::class.java))
                    stopService(Intent(this, ProxyGuardService::class.java))
                    val restored = if (operation == ACTION_RESTORE_FROM && snapshot != null)
                        CloudSync.restoreFrom(this, snapshot) else CloudSync.restore(this)
                    finishJob(operation, restored,
                        if (restored) "Encrypted Google Drive restore completed" else "No backup was found")
                }
            } catch (e: InterruptedException) {
                finishJob(operation, false, "Backup operation cancelled")
            } catch (e: Exception) {
                finishJob(operation, false, e.message?.take(160) ?: "Backup operation failed")
            } finally {
                if (lock.isHeld) lock.release()
                running.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf(startId)
            }
        }.apply { name = "ShieldBackup"; start() }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        worker?.interrupt()
        super.onDestroy()
    }

    private fun finishJob(operation: String, ok: Boolean, message: String) {
        saveState(operation, if (ok) "success" else "failed", message, 0L)
        getSystemService(NotificationManager::class.java).notify(
            RESULT_NOTIFICATION_ID,
            notification(message, 0L, false).setOngoing(false).build()
        )
        sendBroadcast(Intent(ACTION_FINISHED).setPackage(packageName)
            .putExtra("ok", ok).putExtra("message", message))
    }

    private fun notification(text: String, bytes: Long, active: Boolean): NotificationCompat.Builder {
        val open = PendingIntent.getActivity(this, 9300, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(if (active) "ShieldProxy backup" else "ShieldProxy backup result")
            .setContentText(if (bytes > 0) "$text - ${bytes / 1024 / 1024} MB" else text)
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .setOngoing(active)
        if (active) {
            val cancel = PendingIntent.getService(this, 9301,
                Intent(this, BackupService::class.java).setAction(ACTION_CANCEL),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            builder.setProgress(0, 0, true).addAction(0, "Cancel", cancel)
        }
        return builder
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Encrypted backup", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun saveState(operation: String, status: String, message: String, bytes: Long) {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
            .putString("operation", operation).putString("status", status)
            .putString("message", message).putLong("bytes", bytes)
            .putLong("updatedAt", System.currentTimeMillis()).apply()
    }

    companion object {
        const val ACTION_FINISHED = "com.privacyshield.proxy.BACKUP_FINISHED"
        private const val ACTION_BACKUP = "com.privacyshield.proxy.BACKUP"
        private const val ACTION_RESTORE = "com.privacyshield.proxy.RESTORE"
        private const val ACTION_RESTORE_FROM = "com.privacyshield.proxy.RESTORE_FROM"
        private const val ACTION_CANCEL = "com.privacyshield.proxy.CANCEL_BACKUP"
        private const val EXTRA_SNAPSHOT = "snapshot"
        private const val CHANNEL_ID = "shieldproxy_backup"
        private const val NOTIFICATION_ID = 41
        private const val RESULT_NOTIFICATION_ID = 42
        private const val PREFS = "backup_job_state"

        fun startBackup(ctx: Context) = start(ctx, ACTION_BACKUP)
        fun startRestore(ctx: Context) = start(ctx, ACTION_RESTORE)
        fun startRestoreFrom(ctx: Context, snapshot: String) =
            ContextCompat.startForegroundService(ctx, Intent(ctx, BackupService::class.java)
                .setAction(ACTION_RESTORE_FROM).putExtra(EXTRA_SNAPSHOT, snapshot))
        fun cancel(ctx: Context) {
            ctx.startService(Intent(ctx, BackupService::class.java).setAction(ACTION_CANCEL))
        }
        private fun start(ctx: Context, action: String) {
            ContextCompat.startForegroundService(ctx,
                Intent(ctx, BackupService::class.java).setAction(action))
        }
    }
}
