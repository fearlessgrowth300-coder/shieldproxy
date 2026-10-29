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
    private const val THROTTLE_MS = 30 * 60 * 1000L   // one report per failing thing per 30 min
    private val lastReported = HashMap<String, Long>()
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
        val report = buildFailureReport(
            kind = "crash",
            detail = err.message ?: "",
            version = appVersion(ctx),
            androidRelease = Build.VERSION.RELEASE,
            device = "${Build.MANUFACTURER} ${Build.MODEL}",
            includeDevice = CrashPrivacy.includeDeviceDetails(ctx),
            extras = emptyMap(),
            memory = if (CrashPrivacy.includeDeviceDetails(ctx)) memoryFields(ctx) else emptyMap(),
            thread = thread.name,
            type = err.javaClass.name,
            stack = trace
        )
        enqueue(ctx, report)
    }

    private fun enqueue(ctx: Context, report: JSONObject) {
        val queue = readQueue(ctx)
        queue.put(report)
        // Keep only the most recent MAX_QUEUED so a crash loop can't fill storage.
        val trimmed = JSONArray()
        for (i in maxOf(0, queue.length() - MAX_QUEUED) until queue.length()) trimmed.put(queue.get(i))
        SecureFileStore.writeText(ctx, QUEUE, trimmed.toString())
    }

    /**
     * Record a failure that is NOT a crash.
     *
     * Every serious defect found on real phones so far failed silently: a clone frozen on its logo, a
     * route stuck on "Checking..." because its proxy answered nothing, a guard that was frozen by the
     * OEM and simply stopped working. None of them threw in this app, so crash reporting saw nothing
     * and each one had to be found with a cable attached to a handset. Reporting outcomes instead of
     * only exceptions is what makes those visible without touching the phone.
     *
     * Same scrubbing rules as a crash: no account, no proxy, no credentials. [key] identifies what
     * failed for throttling only and is never uploaded.
     */
    fun reportFailure(
        ctx: Context,
        kind: String,
        detail: String,
        key: String = kind,
        extras: Map<String, Any?> = emptyMap()
    ) {
        runCatching {
            // A dead proxy re-tests every 60s forever. Without this, one broken route would bury every
            // other signal in the table and burn the user's data uploading the same line all day.
            val now = System.currentTimeMillis()
            synchronized(lastReported) {
                val previous = lastReported["$kind|$key"]
                if (previous != null && now - previous < THROTTLE_MS) return
                lastReported["$kind|$key"] = now
            }
            val includeDevice = CrashPrivacy.includeDeviceDetails(ctx)
            val report = buildFailureReport(
                kind = kind,
                detail = detail,
                version = appVersion(ctx),
                androidRelease = Build.VERSION.RELEASE,
                device = "${Build.MANUFACTURER} ${Build.MODEL}",
                includeDevice = includeDevice,
                extras = extras,
                memory = if (includeDevice) memoryFields(ctx) else emptyMap(),
                now = now
            )
            enqueue(ctx.applicationContext, report)
        }
    }

    private fun memoryFields(ctx: Context): Map<String, Any> = runCatching {
        val am = ctx.getSystemService(android.app.ActivityManager::class.java)
            ?: return@runCatching emptyMap<String, Any>()
        val info = android.app.ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        mapOf(
            "ramMb" to (info.totalMem / (1024 * 1024)),
            "freeRamMb" to (info.availMem / (1024 * 1024)),
            "lowMem" to info.lowMemory
        )
    }.getOrDefault(emptyMap())

    /**
     * Device model, Blackbox user id, and package name are omitted unless [includeDevice] is set.
     * The throttle key is never part of this object.
     */
    internal fun buildFailureReport(
        kind: String,
        detail: String,
        version: String,
        androidRelease: String,
        device: String,
        includeDevice: Boolean,
        extras: Map<String, Any?>,
        memory: Map<String, Any> = emptyMap(),
        now: Long = System.currentTimeMillis(),
        thread: String? = null,
        type: String? = null,
        stack: String? = null
    ): JSONObject {
        val report = JSONObject()
            .put("ts", now)
            .put("kind", kind)
            .put("detail", scrub(detail))
            .put("android", androidRelease)
            .put("ver", version)
        if (thread != null) report.put("thread", thread)
        if (type != null) report.put("type", type)
        if (stack != null) report.put("stack", scrub(stack))
        if (includeDevice) {
            report.put("device", device)
            memory.forEach { (k, v) -> report.put(k, v) }
        }
        val hidden = setOf("userId", "pkg", "package", "device")
        extras.forEach { (k, v) ->
            if (!includeDevice && k in hidden) return@forEach
            report.put(k, if (v is String) scrub(v) else (v ?: JSONObject.NULL))
        }
        return report
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
