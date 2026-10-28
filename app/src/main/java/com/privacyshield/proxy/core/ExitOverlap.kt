package com.privacyshield.proxy.core

import java.security.MessageDigest

/** Non-secret comparison of two Android users' exits. The proxy password is never part of the key. */
object ExitOverlap {
    data class Mark(val userId: Int, val exitIp: String, val proxyKey: String)

    fun proxyKey(server: String, port: Int, username: String): String {
        val raw = "${server.trim().lowercase()}|$port|${username.trim()}"
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8))
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }

    fun warnings(mine: Mark, others: List<Mark>): List<String> {
        val out = ArrayList<String>()
        for (other in others) {
            if (other.userId == mine.userId) continue
            val sameIp = mine.exitIp.isNotBlank() && mine.exitIp.equals(other.exitIp, ignoreCase = true)
            val sameProxy = mine.proxyKey.isNotBlank() && mine.proxyKey == other.proxyKey
            if (!sameIp && !sameProxy) continue
            val why = when {
                sameIp && sameProxy -> "the same exit IP and the same proxy identity"
                sameIp -> "the same exit IP ${mine.exitIp}"
                else -> "the same proxy identity"
            }
            out.add("Android user ${other.userId} is set to $why. Routes in the two profiles can be linked.")
        }
        return out
    }
}
