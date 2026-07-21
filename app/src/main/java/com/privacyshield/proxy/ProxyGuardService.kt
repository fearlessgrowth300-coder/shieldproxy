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
import com.privacyshield.proxy.core.SecureFileStore
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * Proxy kill-switch + connection guard.
 *
 * The user's rule: a clone must NEVER run without a live proxy. Once they open an app we
 *   1. verify the proxy is connected BEFORE the app is entered (done in MainActivity pre-flight),
 *   2. keep testing it every POLL_SECS while the app is open,
 *      with native fail-closed routing covering the interval until the next scheduled check,
 *   3. when the first scheduled health check confirms the proxy or phone network is down,
 *      FORCE-CLOSE the clone (not minimize), and
 *   4. keep the same sticky session on failure and tell the user when it is safe to re-open.
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
        @Volatile var routeId: String, val expectedExitIp: String,
        @Volatile var countryIso: String = ""
    ) {
        @Volatile var strikes = 0
        @Volatile var state = "checking"     // checking | connected | down | recovering
        @Volatile var city = ""
        @Volatile var type = ""
        @Volatile var ip = ""
        @Volatile var aliveSince = 0L        // elapsedRealtime of first OK (session-age readout)
        @Volatile var nextTestAt = 0L        // elapsedRealtime target -> live countdown
        @Volatile var lastRouteCheckAt = 0L
        @Volatile var routeProbeStrikes = 0  // endpoint outages are not route-identity failures
        @Volatile var testing = false
    }

    private lateinit var worker: HandlerThread
    private lateinit var bg: Handler
    private lateinit var ui: Handler
    private lateinit var checks: ExecutorService
    @Volatile private var destroyed = false

    override fun onBind(i: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        destroyed = false
        createChannel()
        worker = HandlerThread("proxy-guard").also { it.start() }
        bg = Handler(worker.looper)
        ui = Handler(mainLooper)
        checks = Executors.newFixedThreadPool(4)
        restoreArmedState()
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
                        val countryIso = intent.getStringExtra("countryIso").orEmpty().lowercase()
                        if (auth != null && uid != null && pkg != null
                            && routeId.isNotBlank() && expectedExitIp.isNotBlank()) {
                            val a = Armed(node, tag, auth, uid, pkg, label, routeId, expectedExitIp, countryIso)
                            a.state = "connected"           // pre-flight already confirmed it
                            a.aliveSince = SystemClock.elapsedRealtime()
                            a.lastRouteCheckAt = SystemClock.elapsedRealtime()
                            a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
                            ARMED[tag] = a
                            ARMED_LAST[tag] = a
                            if (!persistArmedState()) {
                                ARMED.remove(tag)
                                ARMED_LAST.remove(tag)
                                bg.post { BlackBoxBridge.stopClone(this, auth, uid, pkg) }
                            }
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
                    persistArmedState()
                }
                if (ARMED.isEmpty()) { stopSelf(); return START_NOT_STICKY }
                updateNotif()
            }
            ACTION_STOP_ALL -> {
                val snapshot = ARMED.values.toList()
                ARMED.clear()
                ARMED_LAST.clear()
                persistArmedState()
                bg.post { snapshot.forEach { BlackBoxBridge.stopClone(this, it.auth, it.userId, it.pkg) } }
                stopSelf(); return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    /**
     * A foreground service can be recreated with a null Intent after Android kills its process.
     * Keep the exact guarded routes in the account-key encrypted store so that recreation never
     * produces a visible but empty guard. Restored entries are checked immediately rather than
     * inheriting their old in-memory "connected" state.
     */
    private fun restoreArmedState() {
        ARMED.clear()
        ARMED_LAST.clear()
        if (!SecureFileStore.exists(this, STATE_FILE)) return
        val encoded = runCatching { SecureFileStore.readText(this, STATE_FILE) }.getOrElse {
            failClosedGuardRestore(it)
            return
        } ?: return
        val now = SystemClock.elapsedRealtime()
        runCatching {
            val array = JSONArray(encoded)
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                val node = ProxyNode.fromJson(item.getJSONObject("node"))
                val tag = item.getString("tag")
                val auth = item.getString("auth")
                val userId = item.getInt("userId")
                val pkg = item.getString("pkg")
                val label = item.optString("label", pkg)
                val routeId = item.getString("routeId")
                val expectedExitIp = item.getString("expectedExitIp")
                val expectedTag = "bb:$auth:$userId:$pkg"
                if (tag != expectedTag || !node.isValid() || routeId.isBlank() || expectedExitIp.isBlank()) {
                    continue
                }
                val countryIso = item.optString("countryIso", "").lowercase()
                val armed = Armed(node, tag, auth, userId, pkg, label, routeId, expectedExitIp, countryIso).apply {
                    state = "checking"
                    aliveSince = now
                    nextTestAt = now
                    lastRouteCheckAt = 0L
                }
                ARMED[tag] = armed
                ARMED_LAST[tag] = armed
            }
        }.onFailure {
            ARMED.clear()
            ARMED_LAST.clear()
            failClosedGuardRestore(it)
        }
    }

    /** If protected guard state exists but cannot authenticate, stop every configured clone. */
    private fun failClosedGuardRestore(error: Throwable) {
        android.util.Log.e("ProxyGuardService", "Encrypted guard state could not be restored", error)
        bg.post {
            BlackBoxBridge.configuredRoutes(this).forEach { route ->
                BlackBoxBridge.stopClone(this, route.authority, route.userId, route.pkg)
            }
        }
    }

    /** Credentials are written only through SecureFileStore (AES-GCM + account key). */
    private fun persistArmedState(): Boolean = runCatching {
        val array = JSONArray()
        ARMED.values.sortedBy { it.tag }.forEach { armed ->
            array.put(JSONObject().apply {
                put("node", armed.node.toJson())
                put("tag", armed.tag)
                put("auth", armed.auth)
                put("userId", armed.userId)
                put("pkg", armed.pkg)
                put("label", armed.label)
                put("routeId", armed.routeId)
                put("expectedExitIp", armed.expectedExitIp)
                put("countryIso", armed.countryIso)
            })
        }
        SecureFileStore.writeText(this, STATE_FILE, array.toString())
        true
    }.getOrElse {
        android.util.Log.e("ProxyGuardService", "Encrypted guard state could not be saved", it)
        false
    }

    // 1-second ticker: refreshes the live countdown in the notification, and every POLL_SECS kicks
    // off the actual proxy tests on the worker thread.
    private val ticker = object : Runnable {
        override fun run() {
            if (destroyed) return
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
        if (destroyed || checks.isShutdown) return
        val now = SystemClock.elapsedRealtime()
        for (a in ARMED.values.toList()) {
            if (!ARMED.containsKey(a.tag) || a.testing || now < a.nextTestAt) continue
            a.testing = true
            try {
                checks.execute {
                val r = ProxyTester.test(a.node, lookupMetadata = a.countryIso.isBlank())
                a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
                if (r.ok) {
                    if (a.countryIso.isBlank() && r.countryIso.isNotBlank()) {
                        // Guard records created before country binding did not carry the verified
                        // exit country. Upgrade the encrypted BlackBox assignment before allowing
                        // another long-running session, so WhatsApp/Instagram no longer inherit
                        // the physical phone's SIM country. setCloneProxy intentionally closes an
                        // already-running clone; the user reopens it with the corrected identity.
                        val migrated = BlackBoxBridge.setCloneProxy(
                            this, a.auth, a.userId, a.pkg, a.node, r.countryIso
                        )
                        if (migrated.ok && migrated.routeId.isNotBlank()) {
                            a.routeId = migrated.routeId
                            a.countryIso = r.countryIso.lowercase()
                            a.lastRouteCheckAt = 0L
                            persistArmedState()
                            alert(a, "${a.label} - proxy country updated to ${a.countryIso.uppercase()}. Re-open the app.")
                            a.testing = false
                            ui.post { updateNotif() }
                            return@execute
                        }
                    }
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
                            val endpointOnlyFailure = route.state == "EXIT_CHECK_FAILED" &&
                                route.routeId == a.routeId
                            if (endpointOnlyFailure && ++a.routeProbeStrikes < ROUTE_PROBE_STRIKES) {
                                // The independently tested proxy is reachable and the native route
                                // identity still matches. One third-party IP-check timeout is not a
                                // confirmed leak or proxy failure, so keep the fail-closed tunnel and
                                // verify again on the next pass instead of killing a healthy clone.
                                a.lastRouteCheckAt = 0L
                            } else {
                                onRouteViolation(a, route.state.ifBlank { route.error.ifBlank { "route mismatch" } })
                                a.testing = false
                                ui.post { updateNotif() }
                                return@execute
                            }
                        } else {
                            a.routeProbeStrikes = 0
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
            } catch (_: RejectedExecutionException) {
                a.testing = false
                if (!destroyed) ui.post { updateNotif() }
            }
        }
    }

    /** Proxy confirmed unreachable: CLOSE the clone (fail-closed, no leak) but KEEP THE SAME sticky
     *  session. We do NOT auto-rotate anymore — minting a fresh session changes the exit IP, which
     *  logs logged-in accounts (IG etc.) straight OUT. Instead we keep re-testing the SAME session and
     *  recover when it comes back (24h sticky sessions rarely die; a blip is usually transient). */
    private fun onProxyDead(a: Armed) {
        val wasRunning = BlackBoxBridge.isCloneRunning(this, a.auth, a.userId, a.pkg)
        BlackBoxBridge.stopClone(this, a.auth, a.userId, a.pkg)   // <-- CLOSE app, not minimize
        a.state = "down"
        a.city = ""; a.type = ""; a.ip = ""
        a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
        alert(a, if (wasRunning)
            "⚠ ${a.label} — proxy unreachable. App CLOSED to stop any leak. Route reserved; re-open only after the proxy is back."
        else
            "⚠ ${a.label} — proxy unreachable. App remains closed. Route reserved until the proxy is back.")
    }

    private fun onRouteViolation(a: Armed, reason: String) {
        BlackBoxBridge.stopClone(this, a.auth, a.userId, a.pkg)
        a.state = "down"
        a.city = ""; a.type = ""; a.ip = ""
        a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
        alert(a, "${a.label} - route identity changed ($reason). App CLOSED to prevent a cross-clone or direct-IP leak.")
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
                    "🟡 ${a.label} — proxy recovering; app remains closed · rechecking in ${secs}s"
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
        destroyed = true
        try { ui.removeCallbacks(ticker) } catch (_: Exception) {}
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
        private const val FAIL_STRIKES = 1        // first confirmed failure closes the clone
        private const val ROUTE_PROBE_STRIKES = 2 // one IP-check vendor timeout is not confirmation
        private const val STATE_FILE = "proxy_guard_state.sec"
        private const val FG_ID = 4801
        private const val CHANNEL = "proxy_guard"
        private const val CHANNEL_ALERT = "proxy_guard_alert"
        const val ACTION_ARM = "com.privacyshield.proxy.GUARD_ARM"
        const val ACTION_DISARM = "com.privacyshield.proxy.GUARD_DISARM"
        const val ACTION_STOP_ALL = "com.privacyshield.proxy.GUARD_STOP_ALL"

        /** Live armed state, readable by MainActivity to render "connected" chips in the list. */
        val ARMED = ConcurrentHashMap<String, Armed>()
        private val ARMED_LAST = ConcurrentHashMap<String, Armed>()

        fun arm(
            ctx: Context, tag: String, node: ProxyNode, label: String,
            routeId: String, expectedExitIp: String, countryIso: String = ""
        ) {
            ARMED_LAST[tag] = Armed(node, tag,
                tag.split(":", limit = 4).getOrNull(1) ?: "",
                tag.split(":", limit = 4).getOrNull(2)?.toIntOrNull() ?: -1,
                tag.split(":", limit = 4).getOrNull(3) ?: "", label, routeId, expectedExitIp,
                countryIso.lowercase())
            val i = Intent(ctx, ProxyGuardService::class.java)
                .setAction(ACTION_ARM)
                .putExtra("tag", tag)
                .putExtra("label", label)
                .putExtra("node", node.toJson().toString())
                .putExtra("routeId", routeId)
                .putExtra("expectedExitIp", expectedExitIp)
                .putExtra("countryIso", countryIso.lowercase())
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

        /** Restart a previously armed encrypted guard after reboot or package replacement. */
        fun restorePersisted(ctx: Context) {
            if (!SecureFileStore.exists(ctx, STATE_FILE)) return
            val app = ctx.applicationContext
            val intent = Intent(app, ProxyGuardService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) app.startForegroundService(intent)
            else app.startService(intent)
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
