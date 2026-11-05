package com.privacyshield.proxy.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings

/**
 * Per-phone setup that the app cannot grant itself.
 *
 * Background delivery of clone notifications depends on things only the phone's owner can allow, and
 * they are different on every brand. Left unchecked they fail silently: the clone is simply killed or
 * frozen and messages stop, with nothing on screen to explain why. This turns that invisible failure
 * into a short checklist, and points each item at the exact settings page rather than describing it.
 *
 * Deliberately advisory. Nothing here blocks the app, because a user who ignores the list still has a
 * working proxy — they just lose background messages, which is a trade they are allowed to make.
 */
object SetupHealth {

    /**
     * [fix] is an Intent to the relevant settings screen, or null when the brand exposes no reachable
     * page and the user has to be told where to look.
     */
    data class Issue(val title: String, val detail: String, val fix: Intent?)

    /** Manufacturers whose power managers kill or freeze apps regardless of Android's own rules. */
    private val AGGRESSIVE = mapOf(
        "infinix" to "Infinix", "tecno" to "Tecno", "itel" to "itel",
        "xiaomi" to "Xiaomi", "redmi" to "Redmi", "poco" to "POCO",
        "samsung" to "Samsung", "oppo" to "OPPO", "realme" to "realme",
        "vivo" to "vivo", "huawei" to "Huawei", "honor" to "Honor",
        "oneplus" to "OnePlus", "meizu" to "Meizu", "asus" to "ASUS"
    )

    private fun brand(): String? {
        val maker = (Build.MANUFACTURER ?: "").lowercase()
        val brand = (Build.BRAND ?: "").lowercase()
        return AGGRESSIVE.entries.firstOrNull { maker.contains(it.key) || brand.contains(it.key) }?.value
    }

    fun isBatteryExempt(ctx: Context): Boolean = try {
        ctx.getSystemService(PowerManager::class.java)
            ?.isIgnoringBatteryOptimizations(ctx.packageName) == true
    } catch (_: Exception) {
        false
    }

    /** Everything still missing, most important first. Empty means nothing is left to do. */
    fun issues(ctx: Context): List<Issue> {
        val out = mutableListOf<Issue>()

        if (!isBatteryExempt(ctx)) {
            out += Issue(
                "Allow ShieldProxy to run in the background",
                "Without this the phone puts ShieldProxy to sleep, and it can no longer keep your " +
                    "clones' messages coming through.",
                @Suppress("BatteryLife")
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(Uri.parse("package:${ctx.packageName}"))
            )
        }

        val maker = brand()
        if (maker != null) {
            // No brand exposes a documented Intent for these screens, and guessing at internal
            // activity names breaks on every firmware update — so send the user to the app's own
            // settings page, which every brand links onward from.
            out += Issue(
                "Lock ShieldProxy and your container in Recents",
                "$maker phones close apps that are swiped away from the recent-apps screen, which " +
                    "kills your clones' message connection. Open Recents, hold the app card, and " +
                    "choose Lock (padlock). Do it for both apps.",
                null
            )
            out += Issue(
                "Turn off background restrictions for both apps",
                "In $maker's battery settings, allow auto-start and turn off any background freeze " +
                    "or deep-sleep option for ShieldProxy and your container app.",
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(Uri.parse("package:${ctx.packageName}"))
            )
        }
        return out
    }

    /**
     * True when the phone is one of the brands that freezes or kills background apps, so callers can
     * explain *why* messages stop instead of only listing what to tap.
     */
    fun brandName(): String? = brand()
}
