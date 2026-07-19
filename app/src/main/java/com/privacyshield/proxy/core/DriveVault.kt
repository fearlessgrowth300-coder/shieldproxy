package com.privacyshield.proxy.core

import android.content.Context
import androidx.documentfile.provider.DocumentFile
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * End-to-end encrypted, independently authenticated Drive chunks. Google Drive only receives
 * opaque .sbx files. A completion marker is written last so interrupted snapshots are never used.
 */
object DriveVault {
    private const val ROOT = "ShieldBox"
    private const val FORMAT = 1
    private const val CHUNK_SIZE = 8 * 1024 * 1024
    /** How many timestamped snapshots to keep per app (restore-history depth). */
    private const val RETENTION = 10
    private val MAGIC = byteArrayOf('S'.code.toByte(), 'B'.code.toByte(), 'X'.code.toByte(), '1'.code.toByte())

    data class RestoreResult(val restored: Boolean, val createdAt: Long = 0L)

    /** One recoverable point-in-time backup. [name] is the snapshot's folder id (a timestamp). */
    data class Snapshot(val name: String, val createdAt: Long, val plainBytes: Long, val parts: Int)

    fun hasBackup(ctx: Context, appTag: String): Boolean = latestSnapshot(ctx, appTag) != null

    fun backup(ctx: Context, appTag: String, writeZip: (ZipOutputStream) -> Unit) {
        val key = VaultKeyStore.load(ctx) ?: error("Backup encryption is not unlocked")
        val appDir = appDir(ctx, appTag)
        val snapshot = DriveFolderStore.findOrCreateDir(appDir, System.currentTimeMillis().toString())
        val sink = ChunkedEncryptedOutput(ctx, snapshot, appTag, key)
        try {
            ZipOutputStream(sink).use { zip -> writeZip(zip) }
            val manifest = JSONObject()
                .put("format", FORMAT)
                .put("app", appTag)
                .put("createdAt", System.currentTimeMillis())
                .put("parts", sink.partCount)
                .put("plainBytes", sink.plainBytes)
                .put("sha256", sink.sha256)
            writeEncryptedBlob(ctx, snapshot, "complete.sbx", manifest.toString().toByteArray(), key,
                "manifest|$appTag")
            prune(appDir, keep = RETENTION)
        } catch (e: Exception) {
            runCatching { snapshot.delete() }
            throw e
        }
    }

    fun restore(ctx: Context, appTag: String, readZip: (ZipInputStream) -> Unit): RestoreResult =
        restoreSnapshotDir(ctx, appTag, latestSnapshot(ctx, appTag), readZip)

    /** Restore a specific snapshot by its [name] (from [listSnapshots]) instead of the latest. */
    fun restoreByName(
        ctx: Context, appTag: String, name: String, readZip: (ZipInputStream) -> Unit
    ): RestoreResult {
        val snapshot = runCatching {
            appDir(ctx, appTag).listFiles().firstOrNull {
                it.isDirectory && it.name == name && it.findFile("complete.sbx")?.isFile == true
            }
        }.getOrNull()
        return restoreSnapshotDir(ctx, appTag, snapshot, readZip)
    }

    private fun restoreSnapshotDir(
        ctx: Context, appTag: String, snapshot: DocumentFile?, readZip: (ZipInputStream) -> Unit
    ): RestoreResult {
        val key = VaultKeyStore.load(ctx) ?: error("Backup encryption is not unlocked")
        if (snapshot == null) return RestoreResult(false)
        val complete = snapshot.findFile("complete.sbx") ?: return RestoreResult(false)
        val manifest = JSONObject(String(readEncryptedBlob(ctx, complete, key, "manifest|$appTag")))
        if (manifest.optInt("format") != FORMAT || manifest.optString("app") != appTag) {
            error("Unsupported or mismatched backup")
        }
        val expectedParts = manifest.getInt("parts")
        val source = ChunkedEncryptedInput(ctx, snapshot, appTag, key, expectedParts)
        ZipInputStream(source).use { zip -> readZip(zip) }
        if (source.sha256 != manifest.getString("sha256")) error("Backup integrity check failed")
        return RestoreResult(true, manifest.optLong("createdAt"))
    }

    /** Every recoverable snapshot for [appTag], newest first (restore history). */
    fun listSnapshots(ctx: Context, appTag: String): List<Snapshot> = runCatching {
        val key = VaultKeyStore.load(ctx) ?: return emptyList()
        appDir(ctx, appTag).listFiles()
            .filter { it.isDirectory }
            .mapNotNull { dir ->
                val complete = dir.findFile("complete.sbx")?.takeIf { it.isFile } ?: return@mapNotNull null
                val manifest = runCatching {
                    JSONObject(String(readEncryptedBlob(ctx, complete, key, "manifest|$appTag")))
                }.getOrNull() ?: return@mapNotNull null
                Snapshot(
                    name = dir.name ?: return@mapNotNull null,
                    createdAt = manifest.optLong("createdAt", dir.name?.toLongOrNull() ?: 0L),
                    plainBytes = manifest.optLong("plainBytes"),
                    parts = manifest.optInt("parts")
                )
            }
            .sortedByDescending { it.createdAt }
    }.getOrDefault(emptyList())

    /**
     * Recovery-key self-test: proves the currently loaded key can actually encrypt AND decrypt.
     * (a) an in-memory round-trip, and (b) if a real backup exists, that this key decrypts its
     * manifest — i.e. existing backups are genuinely recoverable, not just "present".
     */
    fun recoveryKeySelfTest(ctx: Context, appTag: String): Boolean = runCatching {
        val key = VaultKeyStore.load(ctx) ?: return false
        val probe = "shieldbox-recovery-probe".toByteArray()
        val enc = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key); updateAAD("selftest".toByteArray())
        }
        val ciphertext = enc.doFinal(probe)
        val dec = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, enc.iv)); updateAAD("selftest".toByteArray())
        }
        if (!dec.doFinal(ciphertext).contentEquals(probe)) return false
        val snapshot = latestSnapshot(ctx, appTag) ?: return true   // no backup yet — key is still valid
        val complete = snapshot.findFile("complete.sbx") ?: return true
        readEncryptedBlob(ctx, complete, key, "manifest|$appTag")   // throws if the key can't read it
        true
    }.getOrDefault(false)

    private fun appDir(ctx: Context, appTag: String): DocumentFile {
        val selected = DriveFolderStore.root(ctx) ?: error("Google Drive folder is not connected")
        val owner = VaultKeyStore.ownerHash(ctx) ?: error("Account encryption is not configured")
        val root = DriveFolderStore.findOrCreateDir(selected, ROOT)
        val account = DriveFolderStore.findOrCreateDir(root, owner)
        return DriveFolderStore.findOrCreateDir(account, appTag)
    }

    private fun latestSnapshot(ctx: Context, appTag: String): DocumentFile? = runCatching {
        appDir(ctx, appTag).listFiles()
            .filter { it.isDirectory && it.findFile("complete.sbx")?.isFile == true }
            .maxByOrNull { it.name?.toLongOrNull() ?: 0L }
    }.getOrNull()

    private fun prune(appDir: DocumentFile, keep: Int) {
        appDir.listFiles().filter { it.isDirectory }
            .sortedByDescending { it.name?.toLongOrNull() ?: 0L }
            .drop(keep).forEach { runCatching { it.delete() } }
    }

    private fun aad(appTag: String, index: Int) =
        "ShieldBox|$FORMAT|$appTag|$index".toByteArray()

    private fun createFile(parent: DocumentFile, name: String): DocumentFile {
        parent.findFile(name)?.let { runCatching { it.delete() } }
        return parent.createFile("application/octet-stream", name)
            ?: error("Could not create Drive file $name")
    }

    private fun writeEncryptedBlob(
        ctx: Context,
        parent: DocumentFile,
        name: String,
        plain: ByteArray,
        key: SecretKeySpec,
        aadText: String
    ) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aadText.toByteArray())
        val encrypted = cipher.doFinal(plain)
        val file = createFile(parent, name)
        ctx.contentResolver.openOutputStream(file.uri, "w")!!.use { raw ->
            DataOutputStream(raw).use { out ->
                out.write(MAGIC)
                out.writeInt(FORMAT)
                out.writeInt(cipher.iv.size)
                out.write(cipher.iv)
                out.writeInt(plain.size)
                out.write(encrypted)
            }
        }
    }

    private fun readEncryptedBlob(
        ctx: Context,
        file: DocumentFile,
        key: SecretKeySpec,
        aadText: String
    ): ByteArray {
        val bytes = ctx.contentResolver.openInputStream(file.uri)!!.use { it.readBytes() }
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            require(magic.contentEquals(MAGIC) && input.readInt() == FORMAT) { "Invalid backup file" }
            val iv = ByteArray(input.readInt()).also { input.readFully(it) }
            val plainLength = input.readInt()
            val encrypted = input.readBytes()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.updateAAD(aadText.toByteArray())
            return cipher.doFinal(encrypted).also { require(it.size == plainLength) }
        }
    }

    private class ChunkedEncryptedOutput(
        private val ctx: Context,
        private val snapshot: DocumentFile,
        private val appTag: String,
        private val key: SecretKeySpec
    ) : OutputStream() {
        private val buffer = ByteArray(CHUNK_SIZE)
        private var used = 0
        private var index = 0
        private val digest = MessageDigest.getInstance("SHA-256")
        var plainBytes: Long = 0; private set
        val partCount: Int get() = index
        val sha256: String get() = digest.digest().joinToString("") { "%02x".format(it) }

        override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)

        override fun write(source: ByteArray, offset: Int, length: Int) {
            digest.update(source, offset, length)
            plainBytes += length
            var at = offset
            var left = length
            while (left > 0) {
                val take = minOf(left, buffer.size - used)
                System.arraycopy(source, at, buffer, used, take)
                used += take; at += take; left -= take
                if (used == buffer.size) flushPart()
            }
        }

        override fun close() {
            if (used > 0) flushPart()
        }

        private fun flushPart() {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(aad(appTag, index))
            val encrypted = cipher.doFinal(buffer, 0, used)
            val file = createFile(snapshot, "part-${index.toString().padStart(5, '0')}.sbx")
            ctx.contentResolver.openOutputStream(file.uri, "w")!!.use { raw ->
                DataOutputStream(raw).use { out ->
                    out.write(MAGIC)
                    out.writeInt(FORMAT)
                    out.writeInt(index)
                    out.writeInt(cipher.iv.size)
                    out.write(cipher.iv)
                    out.writeInt(used)
                    out.write(encrypted)
                }
            }
            index++
            used = 0
        }
    }

    private class ChunkedEncryptedInput(
        private val ctx: Context,
        snapshot: DocumentFile,
        private val appTag: String,
        private val key: SecretKeySpec,
        expectedParts: Int
    ) : InputStream() {
        private val parts = snapshot.listFiles().filter {
            it.isFile && it.name?.matches(Regex("part-\\d{5}\\.sbx")) == true
        }.sortedBy { it.name }
        private var nextPart = 0
        private var current = ByteArrayInputStream(ByteArray(0))
        private val digest = MessageDigest.getInstance("SHA-256")
        val sha256: String get() = digest.digest().joinToString("") { "%02x".format(it) }

        init { require(parts.size == expectedParts) { "Backup is missing one or more parts" } }

        override fun read(): Int {
            val one = ByteArray(1)
            return if (read(one, 0, 1) == 1) one[0].toInt() and 0xff else -1
        }

        override fun read(target: ByteArray, offset: Int, length: Int): Int {
            while (current.available() == 0) {
                if (nextPart >= parts.size) return -1
                current = ByteArrayInputStream(decryptPart(parts[nextPart], nextPart))
                nextPart++
            }
            val count = current.read(target, offset, length)
            return count
        }

        private fun decryptPart(file: DocumentFile, expectedIndex: Int): ByteArray {
            val bytes = ctx.contentResolver.openInputStream(file.uri)!!.use { it.readBytes() }
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
                require(magic.contentEquals(MAGIC) && input.readInt() == FORMAT) { "Invalid backup part" }
                require(input.readInt() == expectedIndex) { "Backup parts are out of order" }
                val iv = ByteArray(input.readInt()).also { input.readFully(it) }
                val plainLength = input.readInt()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                cipher.updateAAD(aad(appTag, expectedIndex))
                return cipher.doFinal(input.readBytes()).also {
                    require(it.size == plainLength)
                    digest.update(it)
                }
            }
        }
    }
}
