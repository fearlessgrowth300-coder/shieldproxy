package com.privacyshield.proxy.core

import android.content.Context

/** Default on. Turning it off restores the older "keep the clone open and pause traffic" behavior. */
object KillSwitchStore {
    private const val PREFS = "route_kill_switch"
    private const val KEY = "enabled"
    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY, true)

    fun setEnabled(ctx: Context, enabled: Boolean) {
        prefs(ctx).edit().putBoolean(KEY, enabled).apply()
    }
}
