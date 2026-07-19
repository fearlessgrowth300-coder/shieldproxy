package com.privacyshield.proxy.core

import android.content.Context
import com.privacyshield.proxy.ProxyGuardService
import org.json.JSONObject

/**
 * Remote emergency kill switch. The signed-in user can arm it from ANY device (or in-app); every
 * phone that polls the flag then force-stops all guarded clones and refuses new launches until it's
 * disarmed. The flag lives in Supabase auth user_metadata (no extra table required):
 *   shieldproxy_control = { "kill": bool, "reason": string, "at": epochMs }
 *
 * The last known state is cached locally so [isKilled] is cheap on the main thread and the switch
 * still holds if the network is down (fail-safe: a cached kill stays enforced).
 */
object RemoteControl {
    private const val PREFS = "remote_control"
    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isKilled(ctx: Context): Boolean = prefs(ctx).getBoolean("killed", false)
    fun killedReason(ctx: Context): String = prefs(ctx).getString("reason", "").orEmpty()

    /** Fetch and enforce the remote flag. Runs network — call OFF the main thread. */
    fun check(ctx: Context): Boolean {
        if (!Supabase.isSignedIn(ctx)) return isKilled(ctx)
        val control = runCatching { Supabase.readControl(ctx) }.getOrNull() ?: return isKilled(ctx)
        val kill = control.optBoolean("kill", false)
        val reason = control.optString("reason", "")
        prefs(ctx).edit().putBoolean("killed", kill).putString("reason", reason).apply()
        if (kill) enforce(ctx)
        return kill
    }

    fun checkAsync(ctx: Context) {
        val app = ctx.applicationContext
        Thread { runCatching { check(app) } }.start()
    }

    /** Arm/disarm for ALL of this user's phones. Runs network — call OFF the main thread. */
    fun setKill(ctx: Context, on: Boolean, reason: String) {
        val control = JSONObject()
            .put("kill", on)
            .put("reason", reason)
            .put("at", System.currentTimeMillis())
        Supabase.writeControl(ctx, control)
        prefs(ctx).edit().putBoolean("killed", on).putString("reason", reason).apply()
        if (on) enforce(ctx)
    }

    private fun enforce(ctx: Context) {
        runCatching { ProxyGuardService.stopAll(ctx) }
    }
}
