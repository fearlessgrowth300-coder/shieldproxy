package com.privacyshield.proxy.core

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle

/**
 * Minimal signed handshake endpoint for BlackBox. It exposes readiness and an irreversible,
 * truncated account hash only; it never exposes an email, session token, backup key, or proxy.
 */
class ShieldBridgeProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val result = Bundle()
        if (method != "status") {
            result.putBoolean("ok", false)
            return result
        }
        val ctx = context
        val signedIn = ctx != null && Supabase.isSignedIn(ctx)
        val vaultReady = ctx != null && VaultKeyStore.isReady(ctx)
        result.putBoolean("ok", signedIn && vaultReady)
        result.putBoolean("signedIn", signedIn)
        result.putBoolean("vaultReady", vaultReady)
        result.putString("ownerHash", if (ctx != null && vaultReady) VaultKeyStore.ownerHash(ctx) else null)
        result.putBoolean("driveConnected", ctx != null && DriveFolderStore.isConnected(ctx))
        result.putString("app", "shieldproxy")
        result.putString("versionName", ctx?.let {
            runCatching { it.packageManager.getPackageInfo(it.packageName, 0).versionName }.getOrNull()
        }.orEmpty())
        if (!signedIn || !vaultReady) result.putString("err", "ShieldProxy account is locked")
        return result
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?,
        selectionArgs: Array<out String>?): Int = 0
}
