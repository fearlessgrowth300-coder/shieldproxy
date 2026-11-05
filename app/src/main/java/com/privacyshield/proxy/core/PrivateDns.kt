package com.privacyshield.proxy.core

import android.content.Context
import android.os.Build
import android.provider.Settings

/** Android 9+ Private DNS. "hostname" is strict mode (no plaintext fallback). */
object PrivateDns {
    fun strictHost(mode: String?, specifier: String?): String? {
        if (mode != "hostname") return null
        val host = specifier?.trim().orEmpty()
        if (host.isEmpty() || host.any { it.isWhitespace() } || !host.contains('.')) return null
        return host
    }

    fun strictHost(ctx: Context): String? {
        if (Build.VERSION.SDK_INT < 28) return null
        val resolver = ctx.contentResolver
        return strictHost(
            Settings.Global.getString(resolver, "private_dns_mode"),
            Settings.Global.getString(resolver, "private_dns_specifier")
        )
    }
}
