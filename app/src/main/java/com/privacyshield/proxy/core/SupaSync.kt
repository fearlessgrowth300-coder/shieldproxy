package com.privacyshield.proxy.core

import android.content.Context
import org.json.JSONObject

/**
 * Cloud sync via Supabase (replaces the Google Drive vault). The user's config — proxy library,
 * saved lists, active routing — is stored as ONE JSON blob per user in `public.app_backups`
 * (app='shieldproxy'), protected by per-user RLS.
 *
 * The blob holds the DECRYPTED file contents. That's deliberate: it makes restore independent of
 * the device Keystore / account-recovery key, so signing in on a new phone (or after a key change)
 * always brings the data back. Locally the same files stay encrypted at rest via [SecureFileStore].
 */
object SupaSync {
    /** The config files that define the user's setup. Local state/markers are not synced. */
    private val FILES = listOf("proxies.json", "profiles.json", "routing.json")

    /** Push the current config to Supabase. Safe no-op if signed out or the local store is locked. */
    @Synchronized
    fun push(ctx: Context) {
        if (!Supabase.isSignedIn(ctx) || !VaultKeyStore.isReady(ctx)) return
        val files = JSONObject()
        for (name in FILES) {
            val text = runCatching { SecureFileStore.readText(ctx, name) }.getOrNull() ?: continue
            if (text.isNotEmpty()) files.put(name, text)
        }
        if (files.length() == 0) return
        Supabase.pushBackup(ctx, JSONObject().put("v", 1).put("files", files).toString())
    }

    /** Pull the config from Supabase and write it locally (re-encrypted with this device's key).
     *  Returns true if anything was restored. Requires the account key to be provisioned first. */
    @Synchronized
    fun pull(ctx: Context): Boolean {
        if (!Supabase.isSignedIn(ctx) || !VaultKeyStore.isReady(ctx)) return false
        val raw = Supabase.pullBackup(ctx) ?: return false
        val files = JSONObject(raw).optJSONObject("files") ?: return false
        var restored = false
        for (name in FILES) {
            val text = files.optString(name, "")
            if (text.isNotEmpty()) { SecureFileStore.writeText(ctx, name, text); restored = true }
        }
        return restored
    }

    fun pushAsync(ctx: Context) {
        val app = ctx.applicationContext
        Thread { runCatching { push(app) } }.start()
    }
}
