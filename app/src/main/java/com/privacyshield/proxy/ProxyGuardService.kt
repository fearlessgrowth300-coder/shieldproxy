package com.privacyshield.proxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import com.privacyshield.proxy.core.BlackBoxBridge
import com.privacyshield.proxy.core.ProxyNode
import com.privacyshield.proxy.core.ProxyTester
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * Proxy kill-switch + connection guard.
 *
 * The user's rule: a clone must NEVER run without a live proxy. Once they open an app we
 *   1. verify the proxy is connected BEFORE the app is entered (done in MainActivity pre-flight),
 *   2. keep testing it every POLL_SECS while the app is open,
 *   3. the instant the proxy or the phone network dies, FORCE-CLOSE the clone (not minimize) —
 *      so the real IP can never leak — and
 *   4. if the sticky SESSION expired, auto-rotate to a fresh session and show a countdown for the
 *      proxy to come back online; when it recovers we tell the user to re-open the app.
 *
 * The guard keeps running (foreground service) until the user turns it off. The native connect()
 * hook inside the container is already fail-closed (dead proxy -> ECONNREFUSED, no direct fallback),
 * so even in the seconds before we kill the clone there is no leak between clones; this service is
 * the visible, user-facing enforcement on top of that.
 */
class ProxyGuardService : Service() {

    class Armed(
        @Volatile var node: ProxyNode,
        val tag: String, val auth: String, val userId: Int, val pkg: String, val label: String,
        val routeId: String, val expectedExitIp: String
    ) {
        @Volatile var strikes = 0
        @Volatile var state = "checking"     // checking | connected | down | recovering
        @Volatile var city = ""
        @Volatile var type = ""
        @Volatile var ip = ""
        @Volatile var aliveSince = 0L        // elapsedRealtime of first OK (session-age readout)
        @Volatile var nextTestAt = 0L        // elapsedRealtime target -> live countdown
        @Volatile var rotatedCount = 0
        @Volatile var lastRouteCheckAt = 0L
        @Volatile var testing = false
    }

    private lateinit var worker: HandlerThread
    private lateinit var bg: Handler
    private lateinit var ui: Handler
    private lateinit var checks: ExecutorService

    override fun onBind(i: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        worker = HandlerThread("proxy-guard").also { it.start() }
        bg = Handler(worker.looper)
        ui = Handler(mainLooper)
        checks = Executors.newFixedThreadPool(4)
        startForeground(FG_ID, buildNotification())
        ui.post(ticker)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_ARM -> {
                val nodeJson = intent.getStringExtra("node")
                val tag = intent.getStringExtra("tag")
                if (nodeJson != null && tag != null) {
                    try {
                        val node = ProxyNode.fromJson(org.json.JSONObject(nodeJson))
                        val parts = tag.split(":", limit = 4)
                        val auth = parts.getOrNull(1)
                        val uid = parts.getOrNull(2)?.toIntOrNull()
                        val pkg = parts.getOrNull(3)
                        val label = intent.getStringExtra("label") ?: pkg ?: tag
                        val routeId = intent.getStringExtra("routeId").orEmpty()
                        val expectedExitIp = intent.getStringExtra("expectedExitIp").orEmpty()
                        if (auth != null && uid != null && pkg != null
                            && routeId.isNotBlank() && expectedExitIp.isNotBlank()) {
                            val a = Armed(node, tag, auth, uid, pkg, label, routeId, expectedExitIp)
                            a.state = "connected"           // pre-flight already confirmed it
                            a.aliveSince = SystemClock.elapsedRealtime()
                            a.lastRouteCheckAt = SystemClock.elapsedRealtime()
                            a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
                            ARMED[tag] = a
                            updateNotif()
                        }
                    } catch (_: Exception) {}
                }
            }
            ACTION_DISARM -> {
                val tag = intent.getStringExtra("tag")
                if (tag != null) {
                    ARMED.remove(tag)
                    // Turning the guard OFF for a clone also closes it — the user said "it should not
                    // off until I off it", so an explicit off means stop using that proxy = stop app.
                    val a = ARMED_LAST.remove(tag)
                    if (a != null) bg.post { BlackBoxBridge.stopClone(this, a.auth, a.userId, a.pkg) }
                }
                if (ARMED.isEmpty()) { stopSelf(); return START_NOT_STICKY }
                updateNotif()
            }
            ACTION_STOP_ALL -> {
                val snapshot = ARMED.values.toList()
                ARMED.clear()
                bg.post { snapshot.forEach { BlackBoxBridge.stopClone(this, it.auth, it.userId, it.pkg) } }
                stopSelf(); return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    // 1-second ticker: refreshes the live countdown in the notification, and every POLL_SECS kicks
    // off the actual proxy tests on the worker thread.
    private val ticker = object : Runnable {
        override fun run() {
            if (ARMED.isNotEmpty()) runTests()
            maybeCheckRemote()
            updateNotif()
            if (!ARMED.isEmpty()) ui.postDelayed(this, 1000L)
        }
    }

    @Volatile private var lastRemoteCheck = 0L

    /** Poll the remote emergency kill switch ~every 60s while guarding; check() force-stops all. */
    private fun maybeCheckRemote() {
        val now = SystemClock.elapsedRealtime()
        if (now - lastRemoteCheck < 60_000L) return
        lastRemoteCheck = now
        com.privacyshield.proxy.core.RemoteControl.checkAsync(this)
    }

    private fun runTests() {
        val now = SystemClock.elapsedRealtime()
        for (a in ARMED.values.toList()) {
            if (!ARMED.containsKey(a.tag) || a.testing || now < a.nextTestAt) continue
            a.testing = true
            checks.execute {
                val r = ProxyTester.test(a.node, lookupMetadata = false)
                a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
                if (r.ok) {
                    // A healthy node is not enough: prove the exact running clone still holds the
                    // assignment we armed, has a real proxied exit, and retains DNS/UDP guards.
                    // Mobile/residential nodes may legitimately rotate exit IP inside one session,
                    // so route identity—not byte-for-byte IP pinning—is the isolation proof.
                    val routeDue = SystemClock.elapsedRealtime() - a.lastRouteCheckAt >= ROUTE_VERIFY_SECS * 1000L
                    if (routeDue && BlackBoxBridge.isCloneRunning(this, a.auth, a.userId, a.pkg)) {
                        val route = BlackBoxBridge.verifyRoute(
                            this, a.auth, a.userId, a.pkg, a.expectedExitIp
                        )
                        a.lastRouteCheckAt = SystemClock.elapsedRealtime()
                        if (!route.ok || route.routeId != a.routeId || route.exitIp.isBlank()) {
                            onRouteViolation(a, route.state.ifBlank { route.error.ifBlank { "route mismatch" } })
                            a.testing = false
                            ui.post { updateNotif() }
                            return@execute
                        }
                    }
                    val wasBad = a.state == "down" || a.state == "recovering"
                    a.strikes = 0
                    if (r.city.isNotBlank()) a.city = r.city
                    if (r.type.isNotBlank()) a.type = r.type
                    a.ip = r.ip
                    a.state = "connected"
                    if (a.aliveSince == 0L) a.aliveSince = SystemClock.elapsedRealtime()
                    if (wasBad) alert(a, "✓ ${a.label} — proxy back online (${r.city.ifBlank { r.ip }}). Re-open the app.")
                } else if (r.reachableOnly) {
                    // Proxy socket answered but exit IP couldn't be confirmed — network wobble, don't
                    // kill yet, just don't reset the alive clock.
                } else {
                    a.strikes++
                    if (a.strikes >= FAIL_STRIKES && a.state != "down" && a.state != "recovering") {
                        onProxyDead(a)
                    }
                }
                a.testing = false
                ui.post { updateNotif() }
            }
        }
    }

    /** Proxy confirmed unreachable: CLOSE the clone (fail-closed, no leak) but KEEP THE SAME sticky
     *  session/IP. We do NOT auto-rotate anymore — minting a fresh session changes the exit IP, which
     *  logs logged-in accounts (IG etc.) straight OUT. Instead we keep re-testing the SAME session and
     *  recover when it comes back (24h sticky sessions rarely die; a blip is usually transient). */
    private fun onProxyDead(a: Armed) {
        val wasRunning = BlackBoxBridge.isCloneRunning(this, a.auth, a.userId, a.pkg)
        BlackBoxBridge.stopClone(this, a.auth, a.userId, a.pkg)   // <-- CLOSE app, not minimize
        a.state = "down"
        a.city = ""; a.type = ""; a.ip = ""
        a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
        alert(a, if (wasRunning)
            "⚠ ${a.label} — proxy unreachable. App CLOSED to stop any leak. Keeping your IP; will reconnect when the proxy is back."
        else
            "⚠ ${a.label} — proxy unreachable. Keeping your IP; will reconnect when it's back.")
    }

    private fun onRouteViolation(a: Armed, reason: String) {
        BlackBoxBridge.stopClone(this, a.auth, a.userId, a.pkg)
        a.state = "down"
        a.city = ""; a.type = ""; a.ip = ""
        a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
        alert(a, "${a.label} - route identity changed ($reason). App CLOSED to prevent a cross-clone or direct-IP leak.")
    }

    private fun pushProxy(a: Armed) {
        try {
            val e = android.os.Bundle().apply {
                putInt("userId", a.userId); putString("pkg", a.pkg)
                putString("type", a.node.type); putString("server", a.node.server); putInt("port", a.node.port)
                putString("username", a.node.username); putString("password", a.node.password)
            }
            contentResolver.call(BlackBoxBridge.baseFor(a.auth), "setProxy", null, e)
        } catch (_: Exception) {}
    }

    private fun newSessionId(): String {
        // Fresh alphanumeric token; SOAX treats a new sessionid as a brand-new sticky IP.
        val n = System.nanoTime() + SEQ.getAndIncrement().toLong() * 1_000_003L
        val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        val sb = StringBuilder("sp")
        var v = if (n < 0) -n else n
        repeat(10) { sb.append(chars[(v % 36).toInt()]); v /= 36 }
        return sb.toString()
    }

    // ---- Notification --------------------------------------------------------

    private fun updateNotif() {
        try { (getSystemService(NotificationManager::class.java)).notify(FG_ID, buildNotification()) } catch (_: Exception) {}
    }

    private fun buildNotification(): Notification {
        val now = SystemClock.elapsedRealtime()
        val lines = ARMED.values.map { a ->
            when (a.state) {
                "connected" -> {
                    val ttl = a.node.sessionLengthSec()
                    val ageMin = if (a.aliveSince > 0) ((now - a.aliveSince) / 60000).toInt() else 0
                    val sess = when {
                        ttl != null -> " · session ${ageMin}m/${ttl / 60}m"
                        else -> if (ageMin > 0) " · ${ageMin}m" else ""
                    }
                    "🟢 ${a.label} — connected ${a.city.ifBlank { a.ip }}${if (a.type.isNotBlank()) " · ${a.type}" else ""}$sess"
                }
                "recovering" -> {
                    val secs = ((a.nextTestAt - now) / 1000).coerceAtLeast(0)
                    "🟡 ${a.label} — proxy down, rotated${if (a.rotatedCount > 1) " x${a.rotatedCount}" else ""} · rechecking in ${secs}s"
                }
                "down" -> "🔴 ${a.label} — proxy DOWN (no session to rotate). App closed."
                else -> "⏳ ${a.label} — checking…"
            }
        }
        val title = if (ARMED.size == 1) "Proxy guard — 1 clone" else "Proxy guard — ${ARMED.size} clones"
        val body = if (lines.isEmpty()) "No clones armed." else lines.joinToString("\n")

        val stopAll = PendingIntent.getService(
            this, 1, Intent(this, ProxyGuardService::class.java).setAction(ACTION_STOP_ALL),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val open = PendingIntent.getActivity(
            this, 2, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(lines.firstOrNull() ?: body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(0, "Turn guard off (close apps)", stopAll)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    /** High-priority one-shot heads-up so the user notices an app was closed / came back. */
    private fun alert(a: Armed, msg: String) {
        try {
            val n = NotificationCompat.Builder(this, CHANNEL_ALERT)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("ShieldProxy — kill-switch")
                .setContentText(msg)
                .setStyle(NotificationCompat.BigTextStyle().bigText(msg))
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(
                    PendingIntent.getActivity(this, 3, Intent(this, MainActivity::class.java),
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                )
                .build()
            (getSystemService(NotificationManager::class.java)).notify(a.tag.hashCode(), n)
        } catch (_: Exception) {}
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Proxy guard",
                NotificationManager.IMPORTANCE_LOW).apply { description = "Live proxy connection status" })
            nm.createNotificationChannel(NotificationChannel(CHANNEL_ALERT, "Proxy kill-switch alerts",
                NotificationManager.IMPORTANCE_HIGH).apply { description = "App closed / proxy back online" })
        }
    }

    override fun onDestroy() {
        try { checks.shutdownNow() } catch (_: Exception) {}
        try { worker.quitSafely() } catch (_: Exception) {}
        super.onDestroy()
    }

    companion object {
        // Ten guarded clones must not create a continuous burst of extra SOAX tunnels. Native
        // BlackBox routing is already fail-closed per connection, so a slower health probe cannot
        // fall back to the phone IP; it only delays the user-facing "proxy down" decision.
        private const val POLL_SECS = 60          // proxy re-test cadence while an app is open
        private const val ROUTE_VERIFY_SECS = 60  // heavier in-guest exit/guard proof
        private const val FAIL_STRIKES = 3        // consecutive failures before we kill the clone
        private const val FG_ID = 4801
        private const val CHANNEL = "proxy_guard"
        private const val CHANNEL_ALERT = "proxy_guard_alert"
        const val ACTION_ARM = "com.privacyshield.proxy.GUARD_ARM"
        const val ACTION_DISARM = "com.privacyshield.proxy.GUARD_DISARM"
        const val ACTION_STOP_ALL = "com.privacyshield.proxy.GUARD_STOP_ALL"

        private val SEQ = AtomicInteger(0)

        /** Live armed state, readable by MainActivity to render "connected" chips in the list. */
        val ARMED = ConcurrentHashMap<String, Armed>()
        private val ARMED_LAST = ConcurrentHashMap<String, Armed>()

        fun arm(
            ctx: Context, tag: String, node: ProxyNode, label: String,
            routeId: String, expectedExitIp: String
        ) {
            ARMED_LAST[tag] = Armed(node, tag,
                tag.split(":", limit = 4).getOrNull(1) ?: "",
                tag.split(":", limit = 4).getOrNull(2)?.toIntOrNull() ?: -1,
                tag.split(":", limit = 4).getOrNull(3) ?: "", label, routeId, expectedExitIp)
            val i = Intent(ctx, ProxyGuardService::class.java)
                .setAction(ACTION_ARM)
                .putExtra("tag", tag)
                .putExtra("label", label)
                .putExtra("node", node.toJson().toString())
                .putExtra("routeId", routeId)
                .putExtra("expectedExitIp", expectedExitIp)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun disarm(ctx: Context, tag: String) {
            val i = Intent(ctx, ProxyGuardService::class.java).setAction(ACTION_DISARM).putExtra("tag", tag)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun stopAll(ctx: Context) {
            val i = Intent(ctx, ProxyGuardService::class.java).setAction(ACTION_STOP_ALL)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i) else ctx.startService(i)
        }

        /** One-line status for the clone with [tag], or null if not armed. */
        fun statusFor(tag: String): String? {
            val a = ARMED[tag] ?: return null
            return when (a.state) {
                "connected" -> "🟢 Connected${if (a.city.isNotBlank()) " · ${a.city}" else ""}${if (a.type.isNotBlank()) " · ${a.type}" else ""}"
                "recovering" -> "🟡 Down — rotating proxy…"
                "down" -> "🔴 Down — app closed"
                else -> "⏳ Checking…"
            }
        }

        fun isArmed(tag: String): Boolean = ARMED.containsKey(tag)
    }
}
