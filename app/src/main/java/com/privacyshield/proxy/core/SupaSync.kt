package com.privacyshield.proxy.core

import android.content.Context
import org.json.JSONObject

/**
 * Cloud sync via Supabase. Proxy, profile, and routing files are encrypted on this device
 * before they are uploaded. The AES key lives in the Android Keystore and is never uploaded.
 *
 * Version 1 blobs (plaintext files) still restore. The next push rewrites them as version 2.
 * A version 2 blob cannot be opened on a different phone.
 */
object SupaSync {
    /** The config files that define the user's setup. Local state/markers are not synced. */
    private val FILES = listOf("proxies.json", "profiles.json", "routing.json")

    /** Push the current config to Supabase. Safe no-op if signed out or the local store is locked. */
    @Synchronized
    fun push(ctx: Context) {
        if (!Supabase.isSignedIn(ctx) || !VaultKeyStore.isReady(ctx)) return
        val files = LinkedHashMap<String, String>()
        for (name in FILES) {
            val text = runCatching { SecureFileStore.readText(ctx, name) }.getOrNull() ?: continue
            if (text.isNotEmpty()) files[name] = text
        }
        if (files.isEmpty()) return
        val sealed = CloudBackupCrypto.seal(files, DeviceCloudKey.get(ctx))
        Supabase.pushBackup(ctx, sealed)
    }

    /** Pull the config from Supabase and write it locally (re-encrypted with this device's key).
     *  Returns true if anything was restored. Requires the account key to be provisioned first. */
    @Synchronized
    fun pull(ctx: Context): Boolean {
        if (!Supabase.isSignedIn(ctx) || !VaultKeyStore.isReady(ctx)) return false
        val raw = Supabase.pullBackup(ctx) ?: return false
        val opened = runCatching { CloudBackupCrypto.open(raw, DeviceCloudKey.get(ctx)) }.getOrNull()
            ?: return false
        var restored = false
        for (name in FILES) {
            val text = opened.files[name].orEmpty()
            if (text.isNotEmpty()) { SecureFileStore.writeText(ctx, name, text); restored = true }
        }
        return restored
    }

    fun pushAsync(ctx: Context) {
        val app = ctx.applicationContext
        Thread { runCatching { push(app) } }.start()
    }
}
