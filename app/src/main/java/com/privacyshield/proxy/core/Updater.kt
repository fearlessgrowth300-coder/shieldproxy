package com.privacyshield.proxy.core

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * In-app updater. On launch the app checks a small JSON in Supabase Storage; if it lists a newer
 * versionCode than the installed one, the UI offers "Update now", which downloads the APK and opens
 * the system installer. Works for sideloaded apps (no Play Store). Publish a new release by
 * uploading the APK + bumping latest.json in the `app-releases` bucket (see supabase/publish.md).
 */
object Updater {
    private const val METADATA_URL =
        "https://oqyrbdvehvqdcpglaojo.supabase.co/storage/v1/object/public/app-releases/shieldproxy/latest.json"

    data class Release(val versionCode: Int, val versionName: String, val apkUrl: String, val notes: String)

    /** A newer release than what's installed, or null. Runs network — call OFF the main thread. */
    fun check(ctx: Context): Release? {
        val json = runCatching { fetch(METADATA_URL) }.getOrNull() ?: return null
        val o = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val r = Release(o.optInt("versionCode"), o.optString("versionName"),
            o.optString("apkUrl"), o.optString("notes"))
        return if (r.versionCode > installedVersionCode(ctx) && r.apkUrl.isNotBlank()) r else null
    }

    fun checkAsync(ctx: Context, onFound: (Release) -> Unit) {
        val app = ctx.applicationContext
        Thread {
            val r = runCatching { check(app) }.getOrNull() ?: return@Thread
            main { onFound(r) }
        }.start()
    }

    /** Download the APK (reporting 0..100) and launch the installer. */
    fun downloadAndInstall(ctx: Context, release: Release, onProgress: (Int) -> Unit, onError: (String) -> Unit) {
        val app = ctx.applicationContext
        Thread {
            try {
                val dir = File(app.filesDir, "updates").apply { mkdirs() }
                dir.listFiles()?.forEach { it.delete() }
                val apk = File(dir, "update-${release.versionCode}.apk")
                val conn = (URL(release.apkUrl).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 20000; readTimeout = 120000
                }
                val total = conn.contentLengthLong
                conn.inputStream.use { input ->
                    apk.outputStream().use { out ->
                        val buf = ByteArray(128 * 1024); var read = 0L; var n: Int
                        while (input.read(buf).also { n = it } >= 0) {
                            out.write(buf, 0, n); read += n
                            if (total > 0) main { onProgress(((read * 100) / total).toInt()) }
                        }
                    }
                }
                install(app, apk)
            } catch (e: Exception) {
                main { onError(e.message ?: "Download failed") }
            }
        }.start()
    }

    private fun install(ctx: Context, apk: File) {
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", apk)
        ctx.startActivity(Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        })
    }

    private fun installedVersionCode(ctx: Context): Int = runCatching {
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode.toInt()
        else @Suppress("DEPRECATION") pi.versionCode
    }.getOrDefault(Int.MAX_VALUE)   // unknown → don't nag

    private fun fetch(url: String): String {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000; readTimeout = 15000
        }
        return c.inputStream.bufferedReader().use { it.readText() }
    }

    private fun main(block: () -> Unit) = Handler(Looper.getMainLooper()).post(block)
}
