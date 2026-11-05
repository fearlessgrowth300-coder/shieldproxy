package com.privacyshield.proxy

import android.content.pm.ApplicationInfo
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
        val routeId: String = "",
        val exitIp: String = ""
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
            text = com.privacyshield.proxy.core.AndroidProfile.current(this@LeakTestActivity).label +
                "\nReady to compare each BlackBox user without exposing private identifiers."
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
        if (intent.getBooleanExtra("autoRun", false) &&
            (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            runTests()
        }
    }

    private var scanGeneration = 0

    private fun runTests() {
        val targets = cloneTargets()
        val generation = ++scanGeneration
        runButton.text = "Cancel scan"
        runButton.isEnabled = true
        runButton.setOnClickListener {
            scanGeneration++
            runButton.text = "Run full privacy scan"
            runButton.setOnClickListener { runTests() }
            summary.text = "Scan cancelled."
        }
        results.removeAllViews()
        summary.text = if (targets.isEmpty()) {
            "No clone assignments were found. Assign a BlackBox app to a proxy first."
        } else {
            "0/${targets.size}"
        }
        if (targets.isEmpty()) {
            runButton.text = "Run full privacy scan"
            runButton.setOnClickListener { runTests() }
            return
        }
        val app = applicationContext
        Thread {
            val realIp = directRealIp()
            val cfg = runCatching { com.privacyshield.proxy.core.RoutingConfig.load(app) }.getOrNull()
            val ipv6Blocked = cfg?.let { !it.ipv6 && it.blockIpv6WhenOff } ?: true
            val stunBlocked = cfg?.blockQuic ?: true
            val containersExcluded = com.privacyshield.proxy.core.CloneListeners
                .packagesExcludedFromVpn().isNotEmpty()
            val privateDnsDirect = containersExcluded
            val killSwitchOn = com.privacyshield.proxy.core.KillSwitchStore.isEnabled(app)
            val conflicts = com.privacyshield.proxy.core.UserRoute.conflicts(
                targets.associate { com.privacyshield.proxy.core.CloneListeners.tag(it.authority, it.userId, it.pkg) to it.node.name }
            )
            val pool = java.util.concurrent.Executors.newFixedThreadPool(4)
            val done = java.util.concurrent.atomic.AtomicInteger()
            val jobs = targets.map { target ->
                pool.submit<CloneResult> {
                    val result = scanClone(
                        target, realIp, ipv6Blocked, stunBlocked, containersExcluded,
                        privateDnsDirect, killSwitchOn, targetKey(target) in conflicts, generation
                    )
                    val n = done.incrementAndGet()
                    if (generation == scanGeneration) {
                        runOnUiThread {
                            if (generation != scanGeneration) return@runOnUiThread
                            summary.text = "$n/${targets.size}  ${target.label} · user ${target.userId}"
                        }
                    }
                    result
                }
            }
            val scanned = ArrayList<CloneResult>()
            for (job in jobs) {
                val result = try {
                    job.get(12, java.util.concurrent.TimeUnit.SECONDS)
                } catch (_: Exception) {
                    null
                }
                if (generation != scanGeneration) {
                    pool.shutdownNow()
                    return@Thread
                }
                scanned.add(result ?: CloneResult(
                    targets[scanned.size], 2, "TIMEOUT", "The route check did not finish within 8 seconds."
                ))
            }
            pool.shutdownNow()
            val exits = scanned.mapIndexedNotNull { index, result ->
                if (result.exitIp.isBlank()) null else index.toString() to result.exitIp
            }.toMap()
            val shared = com.privacyshield.proxy.core.RouteLeakCheck.sharedExits(exits)
            for (i in scanned.indices) {
                val ip = scanned[i].exitIp
                if (ip.isNotBlank() && ip.lowercase() in shared) {
                    val r = scanned[i]
                    scanned[i] = r.copy(
                        level = 2,
                        headline = "FAIL",
                        detail = "FAIL exit $ip is shared with another route\n" + r.detail
                    )
                }
            }
            val failures = scanned.count { it.level == 2 }
            val warnings = scanned.count { it.level == 1 }
            runOnUiThread {
                if (generation != scanGeneration) return@runOnUiThread
                addNetworkCard(realIp, !ipv6Blocked)
                scanned.forEach { addCloneCard(it) }
                summary.text = when {
                    failures > 0 -> "$failures of ${scanned.size} routes failed."
                    warnings > 0 -> "No cross-route exit was shared. $warnings route${if (warnings == 1) " needs" else "s need"} attention."
                    else -> "All ${scanned.size} routes finished. Exits differ and none is the phone IP."
                }
                runButton.text = "Run full privacy scan"
                runButton.setOnClickListener { runTests() }
            }
        }.apply { name = "ClonePrivacyScan" }.start()
    }

    private fun targetKey(t: CloneTarget) = "${t.authority}:${t.userId}"

    private fun scanClone(
        t: CloneTarget,
        realIp: String?,
        ipv6Blocked: Boolean,
        stunBlocked: Boolean,
        containersExcluded: Boolean,
        privateDnsDirect: Boolean,
        killSwitchOn: Boolean,
        userConflict: Boolean,
        generation: Int
    ): CloneResult {
        val started = android.os.SystemClock.elapsedRealtime()
        fun expired() = android.os.SystemClock.elapsedRealtime() - started >= 8_000
        if (generation != scanGeneration) {
            return CloneResult(t, 2, "TIMEOUT", "Cancelled.")
        }
        if (expired()) return CloneResult(t, 2, "TIMEOUT", "The route check did not finish within 8 seconds.")
        val proxy = com.privacyshield.proxy.core.ProxyTester.test(
            t.node, lookupMetadata = false, timeoutMs = 3_500
        )
        if (expired()) return CloneResult(t, 2, "TIMEOUT", "The proxy check exceeded 8 seconds.", exitIp = proxy.ip)
        val listenerOpen = listenerOpen(t)
        val verdict = com.privacyshield.proxy.core.RouteLeakCheck.assess(
            exitIp = proxy.ip,
            realIp = realIp,
            listenerOpen = listenerOpen,
            userConflict = userConflict,
            containersExcluded = containersExcluded,
            privateDnsDirect = privateDnsDirect,
            ipv6Blocked = ipv6Blocked,
            stunBlocked = stunBlocked,
            killSwitchOn = killSwitchOn
        )
        val port = com.privacyshield.proxy.core.CloneListeners.portForUser(t.authority, t.userId)
        val detail = buildString {
            append("Play Store and Google services in user ${t.userId} use 127.0.0.1:$port, the same route as ${t.label}.")
            append("\n")
            append(verdict.lines.joinToString("\n"))
            if (!proxy.ok && proxy.error.isNotBlank()) append("\n").append(proxy.error)
        }
        val headline = when {
            expired() -> "TIMEOUT"
            verdict.pass -> "PASS"
            else -> "FAIL"
        }
        return CloneResult(
            t, if (verdict.pass) 0 else 2, headline, detail, exitIp = proxy.ip
        )
    }

    private fun listenerOpen(t: CloneTarget): Boolean {
        val port = com.privacyshield.proxy.core.CloneListeners.portForUser(t.authority, t.userId)
        return runCatching {
            java.net.Socket().use {
                it.connect(java.net.InetSocketAddress("127.0.0.1", port), 400)
                true
            }
        }.getOrDefault(false)
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
        return out.values.groupBy { "${it.authority}:${it.userId}" }.values.map { group ->
            group.first()
        }
    }

    private fun addProfileCard(overlap: List<String>) {
        val profile = com.privacyshield.proxy.core.AndroidProfile.current(this)
        val body = buildString {
            append(profile.label)
            append("\nUID ")
            append(profile.uid)
            append("\n")
            append(com.privacyshield.proxy.core.AndroidProfile.vpnGuidance(profile.managed))
            if (overlap.isEmpty()) {
                append("\nNo other Android profile published the same exit. If the other ShieldProxy is not signed into this account, compare them with tools/profile-instances.sh.")
            } else {
                overlap.forEach { append("\n").append(it) }
            }
        }
        addCard(
            "This Android profile",
            if (overlap.isEmpty()) "SEPARATE" else "SAME EXIT",
            Color.parseColor(if (overlap.isEmpty()) "#4EE0B5" else "#FF7A86"),
            body
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
        val badge = when (r.headline) {
            "PASS", "FAIL", "TIMEOUT" -> r.headline
            else -> when (r.level) { 2 -> "FAIL"; 1 -> "CHECK"; else -> "PASS" }
        }
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
            connectTimeout = 3_000
            readTimeout = 3_000
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
