package com.privacyshield.proxy.core

import mobilebridge.Mobilebridge
import mobilebridge.Protector
import mobilebridge.UidQuery

/**
 * Kotlin front for the gomobile-bound Mihomo (Clash.Meta) engine.
 * The generated Java class is mobilebridge.Mobilebridge (Start -> start, Stop -> stop).
 */
object MihomoCore {

    @Volatile
    var running: Boolean = false
        private set

    /**
     * Install the socket protector so Mihomo's outbound proxy sockets bypass the
     * VPN tun (VpnService.protect). Must be set before start().
     */
    fun setProtector(p: Protector?) {
        try {
            Mobilebridge.setProtector(p)
        } catch (_: Throwable) {
        }
    }

    /** Install the per-connection uid resolver (getConnectionOwnerUid) so
     *  UID/PROCESS-NAME rules work on non-rooted Android. Set before start(). */
    fun setUidResolver(q: UidQuery?) {
        try {
            Mobilebridge.setUidResolver(q)
        } catch (_: Throwable) {
        }
    }

    /** @return empty string on success, else the engine's error text. */
    fun start(homeDir: String, configPath: String): String {
        val err = try {
            Mobilebridge.start(homeDir, configPath) ?: ""
        } catch (t: Throwable) {
            "native start failed: ${t.message}"
        }
        running = err.isEmpty()
        return err
    }

    fun stop() {
        try {
            Mobilebridge.stop()
        } catch (_: Throwable) {
        } finally {
            running = false
        }
    }
}
