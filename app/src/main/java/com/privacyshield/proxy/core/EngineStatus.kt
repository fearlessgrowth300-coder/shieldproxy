package com.privacyshield.proxy.core

/**
 * Cross-process engine state. The VPN service runs in `:vpn`, so the UI
 * process cannot read the service's `running` flag. The service writes this
 * marker and refreshes its timestamp while the core is up.
 */
object EngineStatus {
    const val FRESH_MS = 90_000L

    fun marker(token: String, pid: Int): String = "$token\npid=$pid\n"

    fun token(marker: String): String =
        marker.lineSequence().firstOrNull { it.isNotBlank() && !it.startsWith("pid=") }.orEmpty()

    fun pid(marker: String): Int? =
        Regex("""(?m)^pid=(\d+)\s*$""").find(marker)?.groupValues?.get(1)?.toIntOrNull()

    /**
     * @param pidAlive true when that pid is this app, false when it is some
     * other process, null when the pid cannot be read.
     */
    fun isUp(marker: String, ageMs: Long, pidAlive: (Int) -> Boolean?): Boolean {
        if (marker.isBlank()) return false
        val id = pid(marker) ?: return ageMs in 0 until FRESH_MS
        return when (pidAlive(id)) {
            true -> true
            false -> false
            null -> ageMs in 0 until FRESH_MS
        }
    }
}
