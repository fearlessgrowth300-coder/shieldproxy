package com.privacyshield.proxy.core

/**
 * Kotlin's copy of the tun fd. Mihomo is given a different fd and closes that one itself.
 * [closeOnce] drops the reference before closing, so a second stop is a no-op.
 */
class TunOwner {
    private var handle: AutoCloseable? = null

    fun set(next: AutoCloseable?) {
        synchronized(this) { handle = next }
    }

    fun closeOnce() {
        val current = synchronized(this) {
            val held = handle
            handle = null
            held
        }
        if (current == null) return
        try {
            current.close()
        } catch (_: Exception) {
        }
    }

    companion object {
        /** The number written into Mihomo's config. It must not be the fd Kotlin will close. */
        fun mihomoFd(kotlinFd: Int, duplicate: Int): Int {
            require(kotlinFd >= 0 && duplicate >= 0) { "tun fd is not open" }
            require(kotlinFd != duplicate) { "Mihomo must not share Kotlin's tun fd ($kotlinFd)" }
            return duplicate
        }
    }
}
