package com.privacyshield.proxy.core

import android.content.Context

/** Extra packages that must not share a Blackbox user. The built-in Instagram/WhatsApp set always stays. */
object SensitiveAppStore {
    private const val PREFS = "sensitive_apps"
    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun packages(ctx: Context): Set<String> = AssignmentRules.SENSITIVE + extra(ctx)

    fun extra(ctx: Context): Set<String> =
        prefs(ctx).getStringSet("extra", emptySet()).orEmpty().filter { it.isNotBlank() }.toSet()

    fun setExtra(ctx: Context, packages: Set<String>) {
        prefs(ctx).edit().putStringSet("extra", packages.map { it.trim() }.filter { it.isNotBlank() }.toSet()).apply()
    }
}
