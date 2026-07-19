package com.privacyshield.proxy.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import org.json.JSONObject

/** Persisted access to a folder selected from Android's Google Drive document provider. */
object DriveFolderStore {
    private const val PREFS = "drive_backup_folder"
    private const val KEY_URI = "tree_uri"
    private const val KEY_OWNER = "owner_hash"
    private const val GOOGLE_DRIVE_AUTHORITY = "com.google.android.apps.docs.storage"
    private const val ACCOUNT_MARKER = ".shieldbox-account-v1.json"

    fun save(ctx: Context, uri: Uri, ownerHash: String) {
        require(uri.authority == GOOGLE_DRIVE_AUTHORITY) {
            "Choose Google Drive, not Internal storage or Downloads"
        }
        require(ownerHash.isNotBlank()) { "Sign in before connecting Google Drive" }
        val old = storedUri(ctx)
        ctx.contentResolver.takePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        )
        try {
            val root = DocumentFile.fromTreeUri(ctx, uri)
                ?.takeIf { it.exists() && it.canRead() && it.canWrite() }
                ?: error("The selected Google Drive folder is not writable")
            bindOrVerifyAccount(ctx, root, ownerHash)
        } catch (e: Exception) {
            if (old != uri) release(ctx, uri)
            throw e
        }
        if (old != null && old != uri) release(ctx, old)
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_URI, uri.toString())
            .putString(KEY_OWNER, ownerHash)
            .commit()
    }

    fun root(ctx: Context): DocumentFile? {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val value = prefs.getString(KEY_URI, null) ?: return null
        val activeOwner = VaultKeyStore.ownerHash(ctx) ?: return null
        val uri = Uri.parse(value)
        if (uri.authority != GOOGLE_DRIVE_AUTHORITY) return null
        val root = DocumentFile.fromTreeUri(ctx, uri)
            ?.takeIf { it.exists() && it.canRead() && it.canWrite() }
            ?: return null
        val storedOwner = prefs.getString(KEY_OWNER, null)
        if (storedOwner.isNullOrBlank()) {
            // Upgrade folders selected before account binding was introduced. The marker is the
            // reliable SAF boundary: Android's Drive provider does not promise to expose an email.
            if (runCatching { bindOrVerifyAccount(ctx, root, activeOwner) }.isFailure) return null
            if (!prefs.edit().putString(KEY_OWNER, activeOwner).commit()) return null
        } else if (storedOwner != activeOwner) return null
        return root
    }

    fun isConnected(ctx: Context): Boolean = root(ctx) != null

    private fun bindOrVerifyAccount(ctx: Context, root: DocumentFile, ownerHash: String) {
        val marker = root.findFile(ACCOUNT_MARKER)
        if (marker != null) {
            require(marker.isFile) { "The Drive account marker is invalid" }
            val stored = ctx.contentResolver.openInputStream(marker.uri)?.bufferedReader()?.use { it.readText() }
                ?: error("Could not read the Drive account marker")
            val boundOwner = JSONObject(stored).optString("owner")
            require(boundOwner == ownerHash) {
                "This Drive folder is already connected to a different Shield account"
            }
            return
        }
        val created = root.createFile("application/json", ACCOUNT_MARKER)
            ?: error("Could not bind this Google Drive folder to your account")
        val markerJson = JSONObject().put("version", 1).put("owner", ownerHash).toString()
        ctx.contentResolver.openOutputStream(created.uri, "wt")?.bufferedWriter()?.use { it.write(markerJson) }
            ?: error("Could not write the Drive account marker")
    }

    fun clear(ctx: Context) {
        storedUri(ctx)?.let { release(ctx, it) }
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }

    private fun storedUri(ctx: Context): Uri? = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        .getString(KEY_URI, null)?.let(Uri::parse)

    private fun release(ctx: Context, uri: Uri) = runCatching {
        ctx.contentResolver.releasePersistableUriPermission(
            uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
    }.let { Unit }

    fun findOrCreateDir(parent: DocumentFile, name: String): DocumentFile {
        return parent.findFile(name)?.takeIf { it.isDirectory }
            ?: parent.createDirectory(name)
            ?: error("Could not create Drive folder $name")
    }
}
