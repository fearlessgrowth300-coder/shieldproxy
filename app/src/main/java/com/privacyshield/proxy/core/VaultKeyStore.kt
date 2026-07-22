package com.privacyshield.proxy.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Wraps the account backup key with a device-local Android Keystore key. */
object VaultKeyStore {
    private const val PREFS = "drive_vault_key"
    private const val KEY_ALIAS_SUFFIX = ".shieldbox.drive.wrap.v1"
    private const val KEY_VERSION = 2

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private fun alias(ctx: Context) = ctx.packageName + KEY_ALIAS_SUFFIX

    fun isReady(ctx: Context): Boolean = prefs(ctx).getInt("version", 0) == KEY_VERSION && load(ctx) != null

    fun provision(ctx: Context, email: String, accountKey: ByteArray) {
        require(accountKey.size == 32) { "Invalid account backup key" }
        val normalizedEmail = email.trim().lowercase()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey(ctx))
        val encrypted = cipher.doFinal(accountKey)
        prefs(ctx).edit()
            .putInt("version", KEY_VERSION)
            .putString("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .putString("key", Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .putString("owner", ownerHash(normalizedEmail))
            .apply()
    }

    fun load(ctx: Context): SecretKeySpec? = try {
        val p = prefs(ctx)
        val iv = Base64.decode(p.getString("iv", null), Base64.NO_WRAP)
        val encrypted = Base64.decode(p.getString("key", null), Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(ctx), GCMParameterSpec(128, iv))
        SecretKeySpec(cipher.doFinal(encrypted), "AES")
    } catch (_: Exception) {
        null
    }

    fun ownerHash(ctx: Context): String? = prefs(ctx).getString("owner", null)

    fun belongsTo(ctx: Context, email: String): Boolean =
        ownerHash(ctx) == ownerHash(email.trim().lowercase())

    fun clear(ctx: Context) {
        prefs(ctx).edit().clear().apply()
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            ks.deleteEntry(alias(ctx))
        }
    }

    private fun ownerHash(email: String): String = MessageDigest.getInstance("SHA-256")
        .digest(email.toByteArray(StandardCharsets.UTF_8))
        .take(12).joinToString("") { "%02x".format(it) }

    private fun wrappingKey(ctx: Context): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias(ctx), null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    alias(ctx),
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
            generateKey()
        }
    }
}
