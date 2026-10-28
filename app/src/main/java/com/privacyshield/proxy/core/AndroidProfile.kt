package com.privacyshield.proxy.core

import android.content.Context
import android.os.Build
import android.os.Process
import android.os.UserManager

/**
 * Which Android user this process is. A work profile is a second user with its own UID,
 * VPN, credential storage, and app data. User 0 keeps the historical key names so an
 * existing personal install does not lose its session or backup key.
 */
object AndroidProfile {
    const val PER_USER_RANGE = 100_000

    fun userIdOf(uid: Int): Int = uid / PER_USER_RANGE

    /** Personal profile keeps [base]. Every other Android user gets its own suffix. */
    fun backupApp(base: String, userId: Int): String =
        if (userId == 0) base else "$base-u$userId"

    fun keyAlias(base: String, userId: Int): String =
        if (userId == 0) base else "$base.u$userId"

    fun label(userId: Int, managed: Boolean): String =
        if (managed) "Work profile (Android user $userId)"
        else "Personal profile (Android user $userId)"

    fun vpnSessionName(userId: Int, managed: Boolean): String =
        if (managed) "ShieldProxy work u$userId" else "ShieldProxy u$userId"

    fun vpnGuidance(managed: Boolean): String {
        val where = if (managed)
            "Open Settings inside this work profile (not the personal profile's Settings)."
        else
            "Open Settings for this Android user."
        return "$where Then go to Network & internet → VPN → ShieldProxy and turn on " +
            "Always-on VPN and Block connections without VPN. Each profile has its own VPN " +
            "and its own kill switch. Setting them in one profile does not set them in the other."
    }

    fun current(ctx: Context): Snapshot {
        val uid = Process.myUid()
        val userId = userIdOf(uid)
        val managed = managedProfile(ctx)
        return Snapshot(userId, uid, managed)
    }

    data class Snapshot(val userId: Int, val uid: Int, val managed: Boolean) {
        val label: String get() = AndroidProfile.label(userId, managed)
        fun backupApp(base: String) = AndroidProfile.backupApp(base, userId)
        fun keyAlias(base: String) = AndroidProfile.keyAlias(base, userId)
    }

    private fun managedProfile(ctx: Context): Boolean {
        val um = ctx.getSystemService(UserManager::class.java) ?: return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return runCatching { um.isManagedProfile }.getOrDefault(false)
        }
        return runCatching {
            val method = UserManager::class.java.getMethod("isManagedProfile", Int::class.javaPrimitiveType)
            method.invoke(um, userIdOf(Process.myUid())) as Boolean
        }.getOrDefault(false)
    }
}
