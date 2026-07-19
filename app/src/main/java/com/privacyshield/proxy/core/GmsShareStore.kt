package com.privacyshield.proxy.core

import android.content.Context

/**
 * Remembers which BlackBox users have shared-GMS / keep-alive push notifications turned on.
 *
 * When it's on for a user, every clone under that user MUST exit through one consistent proxy —
 * a mismatch between the always-on GMS/push connection and the app's own connection exits on two
 * different IPs and links the account. [AssignmentRules] enforces that at save time.
 */
object GmsShareStore {
    private const val PREFS = "gms_share"
    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private fun key(authority: String, userId: Int) = "$authority:$userId"

    fun setEnabled(ctx: Context, authority: String, userId: Int, on: Boolean) {
        prefs(ctx).edit().putBoolean(key(authority, userId), on).apply()
    }

    fun isEnabled(ctx: Context, authority: String, userId: Int): Boolean =
        prefs(ctx).getBoolean(key(authority, userId), false)
}
