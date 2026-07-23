package com.privacyshield.proxy.core

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.UUID

/** Downloads only a newer APK that is the expected package and is signed by this installed app. */
object Updater {
    private const val METADATA_URL =
        "https://oqyrbdvehvqdcpglaojo.supabase.co/storage/v1/object/public/app-releases/shieldproxy/latest.json"
    private const val MAX_APK_BYTES = 350L * 1024L * 1024L
    private const val MAX_METADATA_CHARS = 128 * 1024
    private val SHA256 = Regex("^[0-9a-fA-F]{64}$")

    data class Release(
        val versionCode: Int,
        val versionName: String,
        val packageName: String,
        val apkUrl: String,
        val sha256: String,
        val notes: String,
        val rolloutPercent: Int
    )

    fun check(ctx: Context): Release? {
        val json = runCatching { fetch(METADATA_URL) }.getOrNull() ?: return null
        val o = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val release = Release(
            o.optInt("versionCode"),
            o.optString("versionName").take(40),
            o.optString("packageName"),
            o.optString("apkUrl"),
            o.optString("sha256"),
            o.optString("notes").take(4000),
            if (o.has("rolloutPercent")) o.optInt("rolloutPercent").coerceIn(0, 100) else 100
        )
        val secureUrl = runCatching {
            URL(release.apkUrl).protocol.equals("https", ignoreCase = true)
        }.getOrDefault(false)
        return if (release.versionCode > installedVersionCode(ctx)
            && release.packageName == ctx.packageName
            && secureUrl
            && SHA256.matches(release.sha256)
            && isEligibleForRollout(ctx, release.versionCode, release.rolloutPercent)
        ) release else null
    }

    private fun isEligibleForRollout(ctx: Context, versionCode: Int, percent: Int): Boolean {
        if (percent <= 0) return false
        if (percent >= 100) return true
        val prefs = ctx.getSharedPreferences("verified_updater", Context.MODE_PRIVATE)
        val installId = prefs.getString("install_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("install_id", it).commit()
        }
        return isBucketEligible(installId, ctx.packageName, versionCode, percent)
    }

    /** Stable, privacy-local cohort. The identifier never leaves the phone. */
    internal fun rolloutBucket(installId: String, packageName: String, versionCode: Int): Int {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$installId:$packageName:$versionCode".toByteArray(Charsets.UTF_8))
        return (((digest[0].toInt() and 0xff) shl 8) or
            (digest[1].toInt() and 0xff)) % 100
    }

    internal fun isBucketEligible(
        installId: String, packageName: String, versionCode: Int, percent: Int
    ): Boolean = percent >= 100 ||
        (percent > 0 && rolloutBucket(installId, packageName, versionCode) < percent)

    fun checkAsync(ctx: Context, onFound: (Release) -> Unit) {
        val app = ctx.applicationContext
        Thread {
            val release = runCatching { check(app) }.getOrNull() ?: return@Thread
            main { onFound(release) }
        }.start()
    }

    fun downloadAndInstall(
        ctx: Context,
        release: Release,
        onProgress: (Int) -> Unit,
        onError: (String) -> Unit
    ) {
        val app = ctx.applicationContext
        Thread {
            val dir = File(app.filesDir, "updates").apply { mkdirs() }
            var partial: File? = null
            try {
                dir.listFiles()?.forEach { it.delete() }
                partial = File(dir, "update-${release.versionCode}.apk.part")
                download(release.apkUrl, partial, onProgress)
                check(fileSha256(partial) == release.sha256.lowercase()) {
                    "Update checksum did not match"
                }
                verifyApk(app, partial, release)
                val ready = File(dir, "update-${release.versionCode}.apk")
                check(partial.renameTo(ready)) { "Could not finalize verified update" }
                main { onProgress(100) }
                install(app, ready)
            } catch (e: Exception) {
                partial?.delete()
                main { onError(e.message ?: "Update failed") }
            }
        }.start()
    }

    private fun download(url: String, target: File, onProgress: (Int) -> Unit) {
        check(URL(url).protocol.equals("https", ignoreCase = true)) { "Insecure update URL blocked" }
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 20_000
            readTimeout = 120_000
            instanceFollowRedirects = true
        }
        try {
            check(connection.responseCode in 200..299) {
                "Update server returned ${connection.responseCode}"
            }
            check(connection.url.protocol.equals("https", ignoreCase = true)) {
                "Insecure update redirect blocked"
            }
            val total = connection.contentLengthLong
            check(total <= 0 || total <= MAX_APK_BYTES) { "Update file is too large" }
            connection.inputStream.use { input ->
                target.outputStream().use { output ->
                    val buffer = ByteArray(128 * 1024)
                    var received = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (count == 0) continue
                        received += count
                        check(received <= MAX_APK_BYTES) { "Update file exceeded the safe size limit" }
                        output.write(buffer, 0, count)
                        if (total > 0) {
                            main { onProgress(((received * 99) / total).toInt().coerceIn(0, 99)) }
                        }
                    }
                    output.fd.sync()
                }
            }
        } finally {
            connection.disconnect()
        }
    }

    @Suppress("DEPRECATION")
    private fun verifyApk(ctx: Context, apk: File, release: Release) {
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES
        else PackageManager.GET_SIGNATURES
        val candidate = ctx.packageManager.getPackageArchiveInfo(apk.absolutePath, flags)
            ?: error("Downloaded file is not a valid APK")
        check(candidate.packageName == ctx.packageName && candidate.packageName == release.packageName) {
            "Update package name did not match"
        }
        val candidateVersion = if (Build.VERSION.SDK_INT >= 28) candidate.longVersionCode
        else candidate.versionCode.toLong()
        check(candidateVersion == release.versionCode.toLong()
                && candidateVersion > installedVersionCode(ctx).toLong()) {
            "Update version did not match"
        }
        val installed = ctx.packageManager.getPackageInfo(ctx.packageName, flags)
        val candidateSigners = signerDigests(candidate)
        check(candidateSigners.isNotEmpty() && candidateSigners == signerDigests(installed)) {
            "Update signing certificate did not match this app"
        }
    }

    @Suppress("DEPRECATION")
    private fun signerDigests(info: PackageInfo): Set<String> {
        val signatures = if (Build.VERSION.SDK_INT >= 28) {
            val signingInfo = info.signingInfo ?: return emptySet()
            if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners
            else signingInfo.signingCertificateHistory
        } else info.signatures
        return signatures.orEmpty().map { sha256(it.toByteArray()) }.toSet()
    }

    private fun installedVersionCode(ctx: Context): Int = runCatching {
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        if (Build.VERSION.SDK_INT >= 28) info.longVersionCode.toInt()
        else @Suppress("DEPRECATION") info.versionCode
    }.getOrDefault(Int.MAX_VALUE)

    private fun install(ctx: Context, apk: File) {
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", apk)
        ctx.startActivity(Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        })
    }

    private fun fetch(url: String): String {
        check(URL(url).protocol.equals("https", ignoreCase = true)) { "Insecure metadata URL blocked" }
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 15_000
            instanceFollowRedirects = true
        }
        return try {
            check(connection.responseCode in 200..299) {
                "Metadata server returned ${connection.responseCode}"
            }
            check(connection.url.protocol.equals("https", ignoreCase = true)) {
                "Insecure metadata redirect blocked"
            }
            connection.inputStream.bufferedReader().use {
                val text = it.readText()
                check(text.length <= MAX_METADATA_CHARS) { "Update metadata is too large" }
                text
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun fileSha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(128 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > 0) digest.update(buffer, 0, count)
            }
        }
        return hex(digest.digest())
    }

    private fun sha256(bytes: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun main(block: () -> Unit) = Handler(Looper.getMainLooper()).post(block)
}
