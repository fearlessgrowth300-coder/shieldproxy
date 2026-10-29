package com.privacyshield.proxy.core

import org.json.JSONObject
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Device-only envelope for the Supabase config blob.
 *
 * Version 1 payloads are the historical plaintext `{v:1, files:{name: text}}` documents.
 * Version 2 encrypts each file with AES-GCM. The key is supplied by the caller and must
 * never be written to Supabase, Drive, or user metadata.
 */
object CloudBackupCrypto {
    private const val VERSION = 2

    data class Opened(val files: Map<String, String>, val legacyPlaintext: Boolean)

    fun seal(files: Map<String, String>, key: SecretKey): String {
        val encoded = JSONObject()
        for ((name, text) in files) {
            encoded.put(name, encrypt(text, key))
        }
        return JSONObject().put("v", VERSION).put("files", encoded).toString()
    }

    fun open(payload: String, key: SecretKey): Opened {
        val root = JSONObject(payload)
        val version = root.optInt("v", 1)
        val filesJson = root.optJSONObject("files") ?: JSONObject()
        if (version < VERSION) {
            val plain = LinkedHashMap<String, String>()
            for (name in filesJson.keys()) plain[name] = filesJson.optString(name, "")
            return Opened(plain, legacyPlaintext = true)
        }
        val files = LinkedHashMap<String, String>()
        for (name in filesJson.keys()) {
            files[name] = decrypt(filesJson.getJSONObject(name), key)
        }
        return Opened(files, legacyPlaintext = false)
    }

    fun keyFromBytes(raw: ByteArray): SecretKey {
        require(raw.size == 32) { "Cloud backup key must be 32 bytes" }
        return SecretKeySpec(raw, "AES")
    }

    private fun encrypt(text: String, key: SecretKey): JSONObject {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Let the provider choose the IV. Android Keystore rejects a caller IV when
        // randomized encryption is required, which is the default for a hardware-backed key.
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val ct = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        return JSONObject()
            .put("iv", Base64.getEncoder().encodeToString(cipher.iv))
            .put("ct", Base64.getEncoder().encodeToString(ct))
    }

    private fun decrypt(obj: JSONObject, key: SecretKey): String {
        val iv = Base64.getDecoder().decode(obj.getString("iv"))
        val ct = Base64.getDecoder().decode(obj.getString("ct"))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }
}
