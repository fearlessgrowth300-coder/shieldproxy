package com.privacyshield.proxy.core

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File

/**
 * Publishes this Android user's exit without the proxy password.
 * The local file and logcat line are what the adb script reads. The Supabase row is only
 * a non-secret fingerprint so the other profile can warn when both exits match.
 */
object ProfileStatus {
    const val LOG_TAG = "ShieldProfile"
    private const val FILE = "profile_status.txt"
    private const val EXIT_PREFIX = "shieldproxy-exit-"

    @Volatile private var lastKey = ""
    @Volatile private var lastUploadAt = 0L

    fun note(ctx: Context, exitIp: String, server: String, port: Int, username: String) {
        val profile = AndroidProfile.current(ctx)
        val key = if (server.isBlank()) "" else ExitOverlap.proxyKey(server, port, username)
        val body = buildString {
            append("package=com.privacyshield.proxy\n")
            append("user=").append(profile.userId).append('\n')
            append("managed=").append(profile.managed).append('\n')
            append("uid=").append(profile.uid).append('\n')
            append("exitIp=").append(exitIp).append('\n')
            append("proxyKey=").append(key).append('\n')
        }
        runCatching { File(ctx.filesDir, FILE).writeText(body) }
        Log.i(LOG_TAG, "user=${profile.userId} managed=${profile.managed} uid=${profile.uid} exitIp=$exitIp proxyKey=$key")
        if (exitIp.isBlank() && key.isBlank()) return
        val fingerprint = "${profile.userId}|$exitIp|$key"
        val now = System.currentTimeMillis()
        if (fingerprint == lastKey && now - lastUploadAt < 10 * 60 * 1000L) return
        lastKey = fingerprint
        lastUploadAt = now
        if (!Supabase.isSignedIn(ctx)) return
        val row = JSONObject()
            .put("androidUser", profile.userId)
            .put("managed", profile.managed)
            .put("exitIp", exitIp)
            .put("proxyKey", key)
        Thread {
            runCatching { Supabase.pushScoped(ctx, exitApp(profile.userId), row.toString()) }
        }.start()
    }

    fun exitApp(userId: Int) = "${EXIT_PREFIX}u$userId"

    fun warnings(ctx: Context, exitIp: String, server: String, port: Int, username: String): List<String> =
        warningsFor(ctx, listOf(ExitOverlap.Mark(
            AndroidProfile.current(ctx).userId,
            exitIp,
            if (server.isBlank()) "" else ExitOverlap.proxyKey(server, port, username)
        )))

    fun warningsFor(ctx: Context, locals: List<ExitOverlap.Mark>): List<String> {
        if (locals.isEmpty() || !Supabase.isSignedIn(ctx)) return emptyList()
        val others = runCatching { Supabase.pullExitMarks(ctx) }.getOrDefault(emptyList())
        return locals.flatMap { ExitOverlap.warnings(it, others) }.distinct()
    }

    fun localSummary(ctx: Context): String = AndroidProfile.current(ctx).label
}
