package com.privacyshield.proxy

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.card.MaterialCardView
import com.privacyshield.proxy.core.AssignmentRules
import com.privacyshield.proxy.core.BlackBoxBridge
import com.privacyshield.proxy.core.ProfileStore
import com.privacyshield.proxy.core.ProxyNode
import com.privacyshield.proxy.core.ProxyTester
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/**
 * Clone-aware privacy scan. Each BlackBox user/package assignment is tested independently. The
 * scan compares only a one-way identity digest; raw Android IDs, IMEIs, GAIDs and DRM identifiers
 * never leave BlackBox.
 */
class LeakTestActivity : AppCompatActivity() {

    private data class CloneTarget(
        val profileName: String,
        val authority: String,
        val userId: Int,
        val pkg: String,
        val label: String,
        val node: ProxyNode
    )

    private data class CloneResult(
        val target: CloneTarget,
        val level: Int,
        val headline: String,
        val detail: String,
        val identityDigest: String = "",
        val routeId: String = ""
    )

    private lateinit var results: LinearLayout
    private lateinit var runButton: Button
    private lateinit var summary: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = dp(20)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, dp(24), pad, dp(32))
            setBackgroundColor(Color.parseColor("#071521"))
        }
        root.addView(TextView(this).apply {
            text = "Privacy scan"
            textSize = 28f
            setTextColor(Color.WHITE)
            setTypeface(typeface, Typeface.BOLD)
        })
        root.addView(TextView(this).apply {
            text = "Identity and route verification for every isolated clone"
            textSize = 14f
            setTextColor(Color.parseColor("#9CB0BF"))
            setPadding(0, dp(4), 0, dp(18))
        })
        summary = TextView(this).apply {
            text = "Ready to compare each BlackBox user without exposing private identifiers."
            textSize = 14f
            setTextColor(Color.parseColor("#D6E4EC"))
            setPadding(dp(16), dp(14), dp(16), dp(14))
            setBackgroundResource(R.drawable.bg_scan_summary)
        }
        root.addView(summary)
        runButton = Button(this).apply {
            text = "Run full privacy scan"
            isAllCaps = false
            setTextColor(Color.parseColor("#04251F"))
            setBackgroundColor(Color.parseColor("#4EE0B5"))
            setOnClickListener { runTests() }
        }
        root.addView(runButton, LinearLayout.LayoutParams(-1, dp(54)).apply {
            topMargin = dp(16)
            bottomMargin = dp(10)
        })
        results = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(results)
        root.addView(Button(this).apply {
            text = "Back to routes"
            isAllCaps = false
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.TRANSPARENT)
            setOnClickListener { finish() }
        }, LinearLayout.LayoutParams(-1, dp(52)).apply { topMargin = dp(10) })
        setContentView(ScrollView(this).apply {
            isFillViewport = true
            addView(root)
        })
    }

    private fun runTests() {
        val targets = cloneTargets()
        runButton.isEnabled = false
        results.removeAllViews()
        summary.text = if (targets.isEmpty()) {
            "No clone assignments were found. Assign a BlackBox app to a proxy first."
        } else {
            "Scanning ${targets.size} clone route${if (targets.size == 1) "" else "s"}…"
        }
        if (targets.isEmpty()) {
            runButton.isEnabled = true
            return
        }

        Thread {
            val realIp = directRealIp()
            val ipv6Open = ipv6Reachable()
            val scanned = targets.map { scanClone(it, realIp, ipv6Open) }.toMutableList()

            // A duplicate identity digest across different users is a hard isolation failure.
            val duplicateIdentities = scanned.filter { it.identityDigest.isNotBlank() }
                .groupBy { it.identityDigest }
                .filterValues { group -> group.map { "${it.target.authority}:${it.target.userId}" }.distinct().size > 1 }
                .keys
            for (i in scanned.indices) {
                val r = scanned[i]
                if (r.identityDigest in duplicateIdentities) {
                    scanned[i] = r.copy(
                        level = 2,
                        headline = "Identity collision detected",
                        detail = r.detail + "\nThis BlackBox user has the same protected identity as another user. Launch blocked until fixed."
                    )
                }
            }

            val failures = scanned.count { it.level == 2 }
            val warnings = scanned.count { it.level == 1 }
            runOnUiThread {
                addNetworkCard(realIp, ipv6Open)
                scanned.forEach { addCloneCard(it) }
                summary.text = when {
                    failures > 0 -> "$failures clone${if (failures == 1) "" else "s"} failed isolation. Do not use the affected clone until corrected."
                    warnings > 0 -> "Identity separation passed. $warnings route${if (warnings == 1) " needs" else "s need"} attention."
                    else -> "All ${scanned.size} clones have distinct identities and verified proxy routes."
                }
                runButton.isEnabled = true
            }
        }.apply { name = "ClonePrivacyScan" }.start()
    }

    private fun cloneTargets(): List<CloneTarget> {
        val out = LinkedHashMap<String, CloneTarget>()
        for (profile in ProfileStore.load(this)) {
            for ((tag, nodeName) in profile.config.bbMap) {
                val parsed = AssignmentRules.parse(tag) ?: continue
                val node = profile.config.nodes.firstOrNull { it.name == nodeName } ?: continue
                val key = "${parsed.authority}:${parsed.userId}:${parsed.pkg}"
                out[key] = CloneTarget(
                    profileName = profile.name,
                    authority = parsed.authority,
                    userId = parsed.userId,
                    pkg = parsed.pkg,
                    label = appLabel(parsed.pkg),
                    node = node
                )
            }
        }
        return out.values.toList()
    }

    private fun scanClone(t: CloneTarget, realIp: String?, ipv6Open: Boolean): CloneResult {
        val identity = BlackBoxBridge.identityStatus(this, t.authority, t.userId)
        if (!identity.ok || identity.digest.isBlank()) {
            return CloneResult(t, 2, "Identity isolation incomplete",
                identity.error.ifBlank { "BlackBox did not provide a complete protected identity." })
        }

        val proxy = ProxyTester.test(t.node, lookupMetadata = true)
        if (!proxy.ok || proxy.ip.isBlank()) {
            return CloneResult(t, 2, "Proxy unavailable — clone remains closed",
                proxy.error.ifBlank { "The assigned proxy exit could not be verified." }, identity.digest)
        }
        if (proxy.ip == realIp) {
            return CloneResult(t, 2, "Proxy exit equals the phone network",
                "No usable route separation was detected.", identity.digest)
        }

        var route = BlackBoxBridge.verifyRoute(this, t.authority, t.userId, t.pkg, proxy.ip)
        if (!route.ok && route.state == "NOT_RUNNING") {
            val prepared = BlackBoxBridge.prepareRoute(this, t.authority, t.userId, t.pkg)
            if (prepared.ok) route = BlackBoxBridge.verifyRoute(this, t.authority, t.userId, t.pkg, proxy.ip)
        }
        if (!route.ok) {
            return CloneResult(t, 2, "Inside-clone route not verified",
                "The proxy itself works, but the clone process did not prove the same exit. ${route.error}".trim(),
                identity.digest, route.routeId)
        }

        val warning = ipv6Open && !t.node.carriesUdp()
        val location = proxy.city.takeIf { it.isNotBlank() }?.let { " · $it" }.orEmpty()
        return CloneResult(
            t,
            if (warning) 1 else 0,
            if (warning) "Verified with IPv6/UDP guard" else "Identity and route verified",
            "Exit ${route.exitIp.ifBlank { proxy.ip }}$location · Remote DNS · Direct fallback blocked",
            identity.digest,
            route.routeId
        )
    }

    private fun addNetworkCard(realIp: String?, ipv6Open: Boolean) {
        addCard(
            title = "Phone-network baseline",
            badge = if (ipv6Open) "GUARDED" else "BASELINE",
            badgeColor = Color.parseColor(if (ipv6Open) "#F7C873" else "#4EE0B5"),
            body = "Direct IP: ${realIp ?: "unavailable"}\n" +
                    if (ipv6Open) "IPv6 is present; clone IPv6 and unsafe QUIC must remain blocked." else "No direct IPv6 path detected."
        )
    }

    private fun addCloneCard(r: CloneResult) {
        val color = when (r.level) {
            2 -> Color.parseColor("#FF7A86")
            1 -> Color.parseColor("#F7C873")
            else -> Color.parseColor("#4EE0B5")
        }
        val badge = when (r.level) { 2 -> "FAILED"; 1 -> "CHECK"; else -> "ISOLATED" }
        val shortRoute = r.routeId.takeIf { it.isNotBlank() }?.take(10)?.let { "\nRoute ID: $it…" }.orEmpty()
        addCard(
            "${r.target.label} · User ${r.target.userId}", badge, color,
            "${r.target.profileName}\n${r.headline}\n${r.detail}$shortRoute"
        )
    }

    private fun addCard(title: String, badge: String, badgeColor: Int, body: String) {
        val card = MaterialCardView(this).apply {
            radius = dp(18).toFloat()
            cardElevation = 0f
            setCardBackgroundColor(Color.parseColor("#102737"))
            strokeWidth = dp(1)
            strokeColor = Color.parseColor("#214155")
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(15))
        }
        val top = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        top.addView(TextView(this).apply {
            text = title
            textSize = 16f
            setTextColor(Color.WHITE)
            setTypeface(typeface, Typeface.BOLD)
        }, LinearLayout.LayoutParams(0, -2, 1f))
        top.addView(TextView(this).apply {
            text = badge
            textSize = 10f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(badgeColor)
            setPadding(dp(9), dp(5), dp(9), dp(5))
        })
        box.addView(top)
        box.addView(TextView(this).apply {
            text = body
            textSize = 13f
            setTextColor(Color.parseColor("#B7CAD6"))
            setLineSpacing(0f, 1.12f)
            setPadding(0, dp(8), 0, 0)
        })
        card.addView(box)
        results.addView(card, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
    }

    private fun appLabel(pkg: String): String = runCatching {
        val ai = packageManager.getApplicationInfo(pkg, 0)
        packageManager.getApplicationLabel(ai).toString()
    }.getOrElse {
        when (pkg) {
            "com.instagram.android" -> "Instagram"
            "com.whatsapp" -> "WhatsApp"
            "com.google.android.gm" -> "Gmail"
            "com.android.chrome" -> "Chrome"
            "com.fiverr.fiverr" -> "Fiverr"
            "org.telegram.messenger" -> "Telegram"
            else -> pkg.substringAfterLast('.')
        }
    }

    private fun directRealIp(): String? = runCatching {
        val c = (URL("https://api.ipify.org").openConnection() as HttpURLConnection).apply {
            connectTimeout = 8_000
            readTimeout = 8_000
        }
        c.inputStream.bufferedReader().use { it.readText().trim() }.takeIf { it.isNotBlank() }
    }.getOrNull()

    private fun ipv6Reachable(): Boolean = runCatching {
        Socket().use {
            it.connect(InetSocketAddress("2606:4700:4700::1111", 443), 2_500)
            it.isConnected
        }
    }.getOrDefault(false)

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
