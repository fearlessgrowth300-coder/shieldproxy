package com.privacyshield.proxy.core

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable

data class AppInfo(
    val packageName: String,
    val label: String,
    val icon: Drawable?
)

object AppList {
    /** All launchable apps (excluding ourselves), sorted by label. Slow — call off the main thread. */
    fun installed(ctx: Context): List<AppInfo> {
        val pm = ctx.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = pm.queryIntentActivities(intent, 0)
        val seen = HashSet<String>()
        val out = ArrayList<AppInfo>()
        for (ri in resolved) {
            val pkg = ri.activityInfo?.packageName ?: continue
            if (pkg == ctx.packageName) continue
            if (!seen.add(pkg)) continue
            val label = try {
                ri.loadLabel(pm).toString()
            } catch (_: Exception) {
                pkg
            }
            val icon = try {
                ri.loadIcon(pm)
            } catch (_: Exception) {
                null
            }
            out.add(AppInfo(pkg, label, icon))
        }
        out.sortBy { it.label.lowercase() }
        return out
    }

    fun labelFor(ctx: Context, pkg: String): String {
        // BlackBox clone tag: "bb:<authority>:<userId>:<realpkg>"
        if (pkg.startsWith("bb:")) {
            val p = pkg.split(":", limit = 4)
            val auth = p.getOrNull(1) ?: ""
            val uid = p.getOrNull(2) ?: "?"
            val real = p.getOrNull(3) ?: pkg
            val variant = BlackBoxBridge.variantName(auth)
            val name = try {
                ctx.packageManager.getApplicationLabel(ctx.packageManager.getApplicationInfo(real, 0)).toString()
            } catch (_: Exception) { real }
            return "$variant User $uid · $name"
        }
        return try {
            val ai = ctx.packageManager.getApplicationInfo(pkg, 0)
            ctx.packageManager.getApplicationLabel(ai).toString()
        } catch (_: PackageManager.NameNotFoundException) {
            pkg
        }
    }
}
