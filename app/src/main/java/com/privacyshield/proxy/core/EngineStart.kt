package com.privacyshield.proxy.core

/**
 * The engine start sequence. Logged as `ShieldVpn step=<name>` so a hung start
 * shows the last step that completed. Order matters: proxy hostnames are resolved
 * before establish(), and establish() runs off the main thread before Mihomo.
 */
object EngineStart {
    const val TAG = "ShieldVpn"
    const val FOREGROUND = "foreground"
    const val RESOLVE = "resolve-proxy-hosts"
    const val ESTABLISH = "establish"
    const val MIHOMO = "mihomo"
    val STEPS = listOf(FOREGROUND, RESOLVE, ESTABLISH, MIHOMO)
}
