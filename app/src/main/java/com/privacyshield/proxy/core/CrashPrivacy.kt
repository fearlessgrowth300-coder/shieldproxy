package com.privacyshield.proxy.core

import android.content.Context

/** Off by default. Opting in adds the device model, Blackbox user id, and package name to crash reports. */
object CrashPrivacy {
    private const val PREFS = "crash_privacy"
    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun includeDeviceDetails(ctx: Context): Boolean = prefs(ctx).getBoolean("include_device", false)

    fun setIncludeDeviceDetails(ctx: Context, include: Boolean) {
        prefs(ctx).edit().putBoolean("include_device", include).apply()
    }
}
