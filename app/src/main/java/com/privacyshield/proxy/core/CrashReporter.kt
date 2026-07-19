package com.privacyshield.proxy.core

import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Privacy-safe crash reporting. Captures uncaught exceptions, SCRUBS anything that could identify
 * an account or expose a proxy (IPs, credentials, session ids, tokens, emails), stores them in the
 * app's authenticated-encrypted local store, and best-effort uploads when signed in. A crash report
 * never contains which account crashed or which proxy it used.
 */
object CrashReporter {
    private const val QUEUE = "crash_queue.json"
    private const val MAX_QUEUED = 20
    @Volatile private var appCtx: Context? = null

    fun install(ctx: Context) {
        val app = ctx.applicationContext
        appCtx = app
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, err ->
            runCatching { capture(app, thread, err) }
            previous?.uncaughtException(thread, err)
        }
    }

    private fun capture(ctx: Context, thread: Thread, err: Throwable) {
        val trace = StringWriter().also { err.printStackTrace(PrintWriter(it)) }.toString()
        val report = JSONObject()
            .put("ts", System.currentTimeMillis())
            .put("thread", thread.name)
            .put("type", err.javaClass.name)
            .put("msg", scrub(err.message ?: ""))
            .put("stack", scrub(trace))
            .put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
            .put("android", Build.VERSION.RELEASE)
            .put("ver", appVersion(ctx))
        val queue = readQueue(ctx)
        queue.put(report)
        // Keep only the most recent MAX_QUEUED so a crash loop can't fill storage.
        val trimmed = JSONArray()
        for (i in maxOf(0, queue.length() - MAX_QUEUED) until queue.length()) trimmed.put(queue.get(i))
        SecureFileStore.writeText(ctx, QUEUE, trimmed.toString())
    }

    /** Redact everything that could identify an account or expose a proxy. Public for unit checks. */
    fun scrub(input: String): String {
        var t = input
        t = t.replace(Regex("(?i)sessionid-[A-Za-z0-9]+"), "sessionid-<redacted>")
        t = t.replace(Regex("(?i)package-\\d+[A-Za-z0-9\\-]*"), "package-<redacted>")
        t = t.replace(
            Regex("(?i)\\b(password|passwd|pwd|username|user|token|authorization|bearer)\\b\\s*[=:]\\s*\\S+"),
            "$1=<redacted>"
        )
        // JWT-shaped tokens
        t = t.replace(Regex("eyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+"), "<jwt>")
        // emails
        t = t.replace(Regex("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}"), "<email>")
        // IPv4
        t = t.replace(Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"), "<ip>")
        // IPv6 (two-or-more hextet runs)
        t = t.replace(Regex("\\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]+\\b"), "<ip6>")
        return t
    }

    private fun appVersion(ctx: Context): String = runCatching {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "?"
    }.getOrDefault("?")

    private fun readQueue(ctx: Context): JSONArray =
        runCatching { JSONArray(SecureFileStore.readText(ctx, QUEUE) ?: "[]") }.getOrDefault(JSONArray())

    fun pendingCount(ctx: Context): Int = readQueue(ctx).length()

    /** Upload queued reports if signed in; clears the queue only on a confirmed upload. */
    fun flush(ctx: Context) {
        val queue = readQueue(ctx)
        if (queue.length() == 0 || !Supabase.isSignedIn(ctx)) return
        val uploaded = runCatching { Supabase.uploadCrashes(ctx, queue) }.getOrDefault(false)
        if (uploaded) SecureFileStore.writeText(ctx, QUEUE, "[]")
    }

    fun flushAsync(ctx: Context) {
        val app = ctx.applicationContext
        Thread { runCatching { flush(app) } }.start()
    }
}
