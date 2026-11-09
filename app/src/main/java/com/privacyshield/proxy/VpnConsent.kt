package com.privacyshield.proxy

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.io.File

/**
 * VPN consent does not survive an update. [VpnService.prepare] is the only way to show the
 * system dialog again. Background callers cannot show that dialog, so they leave a notification
 * that opens the home screen, which launches it.
 */
object VpnConsent {
    const val EXTRA_ALLOW = "com.privacyshield.proxy.ALLOW_VPN"
    const val MESSAGE = "Tap to allow ShieldProxy VPN"
    private const val CHANNEL_ID = "shieldproxy_consent"
    private const val NOTIF_ID = 44
    private const val WANTED = "engine_wanted.txt"
    private const val NEEDED = "engine_error.txt"

    fun prepare(ctx: Context): Intent? = VpnService.prepare(ctx)

    fun isWanted(ctx: Context): Boolean = File(ctx.filesDir, WANTED).isFile

    fun neededMessage(ctx: Context): String? {
        val file = File(ctx.filesDir, NEEDED)
        val text = runCatching { if (file.isFile) file.readText().trim() else "" }.getOrDefault("")
        return text.ifBlank { null }
    }

    /** Remember that the user asked for the engine, then start it only when consent is already granted. */
    fun startIfPrepared(ctx: Context): Boolean {
        File(ctx.filesDir, WANTED).writeText("1")
        val prep = prepare(ctx)
        if (prep != null) {
            noteNeeded(ctx)
            android.util.Log.i("ShieldVpn", "step=consent-needed")
            return false
        }
        clearNeeded(ctx)
        ContextCompat.startForegroundService(
            ctx,
            Intent(ctx, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_START)
        )
        return true
    }

    fun stop(ctx: Context) {
        runCatching { File(ctx.filesDir, WANTED).delete() }
        clearNeeded(ctx)
        ctx.startService(
            Intent(ctx, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_STOP)
        )
    }

    /** Called when establish() cannot run because this package is not prepared. */
    fun noteNeeded(ctx: Context) {
        runCatching { File(ctx.filesDir, NEEDED).writeText(MESSAGE) }
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "VPN permission", NotificationManager.IMPORTANCE_DEFAULT)
                )
            }
        }
        val open = Intent(ctx, MainActivity::class.java)
            .putExtra(EXTRA_ALLOW, true)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pending = PendingIntent.getActivity(
            ctx, 44, open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("ShieldProxy")
            .setContentText(MESSAGE)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .build()
        nm.notify(NOTIF_ID, notification)
    }

    fun clearNeeded(ctx: Context) {
        runCatching { File(ctx.filesDir, NEEDED).delete() }
        runCatching {
            ctx.getSystemService(NotificationManager::class.java)?.cancel(NOTIF_ID)
        }
    }
}
