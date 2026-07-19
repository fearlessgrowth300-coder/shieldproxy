package com.privacyshield.proxy.core

import android.content.Context
import java.io.File
import java.util.zip.ZipEntry

/** Encrypted Google Drive backup/restore for every file that defines ShieldProxy routing. */
object CloudSync {
    private const val APP_TAG = "shieldproxy"
    private val FILES = setOf(
        "proxies.json",
        "profiles.json",
        "routing.json",
        "rList",
        "profileInstalled"
    )

    fun hasBackup(ctx: Context): Boolean = DriveVault.hasBackup(ctx, APP_TAG)

    @Synchronized
    fun push(ctx: Context) {
        if (!Supabase.isSignedIn(ctx) || !DriveFolderStore.isConnected(ctx)) return
        require(runCatching {
            ProxyLibrary.load(ctx); ProfileStore.load(ctx); RoutingConfig.load(ctx)
        }.isSuccess) {
            "Protected proxy data is locked; backup stopped to preserve older recovery snapshots"
        }
        DriveVault.backup(ctx, APP_TAG) { zip ->
            for (name in FILES.sorted()) {
                val file = File(ctx.filesDir, name)
                if (!file.isFile) continue
                zip.putNextEntry(ZipEntry(name))
                file.inputStream().use { it.copyTo(zip) }
                zip.closeEntry()
            }
        }
        require(verifyLatest(ctx)) { "Drive backup could not be verified" }
    }

    @Synchronized
    fun restore(ctx: Context): Boolean = restoreInto(ctx) { staged ->
        DriveVault.restore(ctx, APP_TAG) { zip -> stageFromZip(zip, staged) }
    }

    /** Restore a specific point-in-time snapshot (from [history]) instead of the latest. */
    @Synchronized
    fun restoreFrom(ctx: Context, snapshotName: String): Boolean = restoreInto(ctx) { staged ->
        DriveVault.restoreByName(ctx, APP_TAG, snapshotName) { zip -> stageFromZip(zip, staged) }
    }

    /** Newest-first list of recoverable snapshots for the restore-history screen. */
    fun history(ctx: Context): List<DriveVault.Snapshot> = DriveVault.listSnapshots(ctx, APP_TAG)

    /** Verify the account recovery key can actually decrypt this account's backups. */
    fun recoveryKeySelfTest(ctx: Context): Boolean = DriveVault.recoveryKeySelfTest(ctx, APP_TAG)

    private inline fun restoreInto(
        ctx: Context,
        pull: (LinkedHashMap<String, ByteArray>) -> DriveVault.RestoreResult
    ): Boolean {
        if (!Supabase.isSignedIn(ctx) || !DriveFolderStore.isConnected(ctx)) return false
        recoverInterruptedRestore(ctx)
        val staged = linkedMapOf<String, ByteArray>()
        val result = pull(staged)
        if (!result.restored) return false
        activateRestore(ctx, staged)
        return staged.isNotEmpty()
    }

    /** Read every entry of a backup ZIP into [staged], enforcing the allow-list and size cap. */
    private fun stageFromZip(zip: java.util.zip.ZipInputStream, staged: LinkedHashMap<String, ByteArray>) {
        var totalBytes = 0L
        while (true) {
            val entry = zip.nextEntry ?: break
            val name = entry.name
            require(!entry.isDirectory && name in FILES && !name.contains('/')) {
                "Backup contains an unexpected file"
            }
            require(name !in staged) { "Backup contains a duplicate file" }
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = zip.read(buffer)
                if (count < 0) break
                totalBytes += count
                require(totalBytes <= 64L * 1024 * 1024) { "Backup is too large" }
                output.write(buffer, 0, count)
            }
            staged[name] = output.toByteArray()
            zip.closeEntry()
        }
    }

    /** Roll back an activation interrupted after its durable marker was committed. */
    @Synchronized
    fun recoverInterruptedRestore(ctx: Context) {
        val marker = File(ctx.filesDir, ".shield-restore-in-progress")
        val backupDir = File(ctx.filesDir, ".shield-restore-before")
        val stageDir = File(ctx.filesDir, ".shield-restore-stage")
        if (marker.exists()) {
            val existing = File(backupDir, "existing.txt").takeIf { it.isFile }
                ?.readLines()?.toSet().orEmpty()
            for (name in FILES) {
                val target = File(ctx.filesDir, name)
                val old = File(backupDir, name)
                if (old.exists()) {
                    target.delete()
                    if (!old.renameTo(target)) error("Could not recover $name")
                } else if (name !in existing) {
                    // The file did not exist before restore; remove a partially activated copy.
                    target.delete()
                }
            }
        }
        marker.delete()
        backupDir.deleteRecursively()
        stageDir.deleteRecursively()
    }

    private fun activateRestore(ctx: Context, restored: Map<String, ByteArray>) {
        val marker = File(ctx.filesDir, ".shield-restore-in-progress")
        val backupDir = File(ctx.filesDir, ".shield-restore-before")
        val stageDir = File(ctx.filesDir, ".shield-restore-stage")
        backupDir.deleteRecursively(); stageDir.deleteRecursively()
        require(backupDir.mkdirs() && stageDir.mkdirs()) { "Could not prepare restore" }
        for ((name, bytes) in restored) {
            val temp = File(stageDir, name)
            java.io.FileOutputStream(temp).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
        }
        java.io.FileOutputStream(File(backupDir, "existing.txt")).use { output ->
            output.write(FILES.filter { File(ctx.filesDir, it).exists() }
                .sorted().joinToString("\n").toByteArray())
            output.fd.sync()
        }
        java.io.FileOutputStream(marker).use { output ->
            output.write(byteArrayOf(1))
            output.fd.sync()
        }
        try {
            for (name in FILES) {
                val current = File(ctx.filesDir, name)
                if (current.exists() && !current.renameTo(File(backupDir, name))) {
                    error("Could not preserve $name")
                }
            }
            for ((name, _) in restored) {
                if (!File(stageDir, name).renameTo(File(ctx.filesDir, name))) {
                    error("Could not activate $name")
                }
            }
            marker.delete()
            backupDir.deleteRecursively()
            stageDir.deleteRecursively()
        } catch (error: Throwable) {
            recoverInterruptedRestore(ctx)
            throw error
        }
    }

    /** Read back every encrypted byte and ZIP CRC without changing local settings. */
    private fun verifyLatest(ctx: Context): Boolean = DriveVault.restore(ctx, APP_TAG) { zip ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            zip.nextEntry ?: break
            while (zip.read(buffer) >= 0) Unit
            zip.closeEntry()
        }
    }.restored

    fun pushAsync(ctx: Context) {
        val app = ctx.applicationContext
        Thread { runCatching { push(app) } }.start()
    }
}
