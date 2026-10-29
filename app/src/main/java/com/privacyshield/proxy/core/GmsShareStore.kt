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
    private const val MIGRATED = "migrated_per_clone_v1"
    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private fun legacyKey(authority: String, userId: Int) = "$authority:$userId"
    private fun tagKey(tag: String) = "tag:$tag"

    /**
     * Older builds stored one flag per Blackbox user. Copy those onto the clone tags that
     * already exist, then leave every new clone off until the user opts in.
     */
    fun migrate(ctx: Context, tags: Collection<String>) {
        val p = prefs(ctx)
        if (p.getBoolean(MIGRATED, false)) return
        val edit = p.edit()
        for (tag in tags) {
            val parsed = AssignmentRules.parse(tag) ?: continue
            if (p.contains(tagKey(tag))) continue
            if (p.getBoolean(legacyKey(parsed.authority, parsed.userId), false)) {
                edit.putBoolean(tagKey(tag), true)
            }
        }
        edit.putBoolean(MIGRATED, true).apply()
    }

    fun setEnabled(ctx: Context, tag: String, on: Boolean) {
        prefs(ctx).edit().putBoolean(tagKey(tag), on).apply()
    }

    /** Off unless this exact clone was opted in. A missing key is off, including after migration. */
    fun isEnabled(ctx: Context, tag: String): Boolean =
        prefs(ctx).getBoolean(tagKey(tag), false)

    @Deprecated("Per-clone flags replaced the user-wide switch", ReplaceWith("isEnabled(ctx, tag)"))
    fun isEnabled(ctx: Context, authority: String, userId: Int): Boolean =
        prefs(ctx).getBoolean(legacyKey(authority, userId), false)
}
