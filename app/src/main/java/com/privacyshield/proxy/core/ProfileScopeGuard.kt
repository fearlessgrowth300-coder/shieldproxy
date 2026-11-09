package com.privacyshield.proxy.core

import android.content.Context

/**
 * App data is already a different directory per Android user. If that directory is ever
 * restored into a different user, drop the copied session and vault instead of reusing them.
 */
object ProfileScopeGuard {
    private const val PREFS = "android_user_scope"

    fun enforce(ctx: Context) {
        val profile = AndroidProfile.current(ctx)
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stored = prefs.getInt("user_id", Int.MIN_VALUE)
        if (stored == Int.MIN_VALUE) {
            prefs.edit().putInt("user_id", profile.userId).apply()
            return
        }
        if (stored != profile.userId) {
            Supabase.clearCopiedSession(ctx)
            VaultKeyStore.clear(ctx)
            prefs.edit().putInt("user_id", profile.userId).apply()
        }
    }
}
