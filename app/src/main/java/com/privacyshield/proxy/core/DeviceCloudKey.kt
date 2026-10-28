package com.privacyshield.proxy.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.SecretKey

/**
 * AES key that exists only inside the Android Keystore on this handset.
 * It is not exported, not synced, and not derivable from the account recovery key.
 */
object DeviceCloudKey {
    private const val SUFFIX = ".shieldproxy.cloudbackup.v1"

    fun get(ctx: Context): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val name = ctx.packageName + SUFFIX
        (ks.getKey(name, null) as? SecretKey)?.let { return it }
        return javax.crypto.KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
            generateKey()
        }
    }
}
