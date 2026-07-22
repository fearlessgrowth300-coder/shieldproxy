package com.privacyshield.proxy.core

import android.content.Context
import android.util.AtomicFile
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Authenticated local storage using the account backup key wrapped by Android Keystore. */
object SecureFileStore {
    private val MAGIC = byteArrayOf('S'.code.toByte(), 'P'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte())

    fun exists(ctx: Context, name: String): Boolean = file(ctx, name).isFile

    fun hasProtectedFiles(ctx: Context): Boolean =
        ctx.filesDir.listFiles().orEmpty().any(::isProtectedFile)

    fun readText(ctx: Context, name: String): String? {
        val target = file(ctx, name)
        if (!target.isFile) return null
        val bytes = target.readBytes()
        if (!bytes.startsWith(MAGIC)) {
            // One-time migration of legacy private plaintext.
            val legacy = bytes.toString(Charsets.UTF_8)
            writeText(ctx, name, legacy)
            return legacy
        }
        val key = VaultKeyStore.load(ctx) ?: error("Account encryption is locked")
        return decryptText(name, bytes, key)
    }

    /** Selects the account key that can authenticate every existing protected local file. This
     * recovers installs created during the former first-login key race without exposing plaintext. */
    fun recoverCompatibleAccountKey(
        ctx: Context,
        email: String,
        candidates: List<ByteArray>
    ): Boolean {
        val protected = ctx.filesDir.listFiles().orEmpty().filter(::isProtectedFile)
        if (protected.isEmpty()) return false
        fun compatible(key: SecretKeySpec): Boolean = protected.all { file ->
            runCatching { decryptText(file.name, file.readBytes(), key) }.isSuccess
        }
        VaultKeyStore.load(ctx)?.takeIf(::compatible)?.let {
            Log.i("SecureFileStore", "Protected key recovery matched current key; files=${protected.size}")
            return true
        }
        for ((index, bytes) in candidates.withIndex()) {
            if (bytes.size != 32) continue
            val key = SecretKeySpec(bytes, "AES")
            if (compatible(key)) {
                VaultKeyStore.provision(ctx, email, bytes)
                Log.i("SecureFileStore", "Protected key recovery matched candidate=$index; files=${protected.size}")
                return true
            }
        }
        Log.w("SecureFileStore", "Protected key recovery found no match; candidates=${candidates.size}; files=${protected.size}")
        return false
    }

    private fun isProtectedFile(candidate: File): Boolean =
        candidate.isFile && candidate.length() >= MAGIC.size && runCatching {
            candidate.inputStream().use { input ->
                val prefix = ByteArray(MAGIC.size)
                input.read(prefix) == prefix.size && prefix.contentEquals(MAGIC)
            }
        }.getOrDefault(false)

    private fun decryptText(name: String, bytes: ByteArray, key: SecretKeySpec): String {
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            val magic = ByteArray(MAGIC.size).also { input.readFully(it) }
            require(magic.contentEquals(MAGIC)) { "Invalid secure file" }
            val ivLength = input.readUnsignedByte()
            require(ivLength in 12..32) { "Invalid secure file IV" }
            val iv = ByteArray(ivLength).also { input.readFully(it) }
            val encrypted = ByteArray(input.available()).also { input.readFully(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.updateAAD(aad(name))
            return cipher.doFinal(encrypted).toString(Charsets.UTF_8)
        }
    }

    fun writeText(ctx: Context, name: String, value: String) {
        val key = VaultKeyStore.load(ctx) ?: error("Account encryption is locked")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad(name))
        val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val bytes = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { out ->
                out.write(MAGIC)
                out.writeByte(cipher.iv.size)
                out.write(cipher.iv)
                out.write(encrypted)
            }
            buffer.toByteArray()
        }
        val atomic = AtomicFile(file(ctx, name))
        val output = atomic.startWrite()
        try {
            output.write(bytes)
            output.fd.sync()
            atomic.finishWrite(output)
        } catch (e: Exception) {
            atomic.failWrite(output)
            throw e
        }
    }

    private fun file(ctx: Context, name: String): File {
        require(name.matches(Regex("[A-Za-z0-9_.-]{1,80}"))) { "Invalid secure filename" }
        return File(ctx.filesDir, name)
    }

    private fun aad(name: String) = "ShieldProxyLocal|1|$name".toByteArray(Charsets.UTF_8)

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
        size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
}
