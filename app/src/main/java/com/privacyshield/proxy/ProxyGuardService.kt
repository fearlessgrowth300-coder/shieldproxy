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
import com.privacyshield.proxy.core.ProfileStore
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
 * Proxy route monitor.
 *
 * The user's rule: a clone must NEVER run without a live proxy. Once they open an app we
 *   1. verify the proxy is connected BEFORE the app is entered (done in MainActivity pre-flight),
 *   2. keep testing it every POLL_SECS while the app is open,
 *      with native fail-closed routing covering the interval until the next scheduled check,
 *   3. if scheduled health checks fail, keep the clone open with its network fail-closed, and
 *   4. keep the same sticky session and resume traffic automatically when it recovers.
 *
 * The guard keeps running (foreground service) until the user turns it off. The native connect()
 * hook inside the container is already fail-closed (dead proxy -> ECONNREFUSED, no direct fallback),
 * so a proxy outage pauses traffic instead of exposing the phone IP. This service provides visible
 * health reporting and detects true route-identity mismatches.
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
                                android.util.Log.e("ProxyGuardService", "Could not persist route-monitor state")
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
                    ARMED_LAST.remove(tag)
                    persistArmedState()
                }
                if (ARMED.isEmpty()) { stopSelf(); return START_NOT_STICKY }
                updateNotif()
            }
            ACTION_STOP_ALL -> {
                ARMED.clear()
                ARMED_LAST.clear()
                persistArmedState()
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
        val claimedTags = runCatching {
            ProfileStore.load(this).flatMapTo(HashSet()) { it.config.bbMap.keys }
        }.getOrElse {
            failClosedGuardRestore(it)
            return
        }
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
                // A monitor is meaningful only while the clone is still claimed by a saved list.
                // Profile edits and cloud restores can otherwise resurrect an old monitor for a
                // moved/deleted assignment and make it appear that the wrong clone was closed.
                if (tag !in claimedTags) continue
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
            persistArmedState()
        }.onFailure {
            ARMED.clear()
            ARMED_LAST.clear()
            failClosedGuardRestore(it)
        }
    }

    /** A corrupt monitor file must not change or rotate any configured clone route. */
    private fun failClosedGuardRestore(error: Throwable) {
        android.util.Log.e("ProxyGuardService", "Encrypted guard state could not be restored", error)
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
            updateNotif()
            if (!ARMED.isEmpty()) ui.postDelayed(this, 1000L)
        }
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
                    val cloneRunning = BlackBoxBridge.isCloneRunning(
                        this, a.auth, a.userId, a.pkg
                    )
                    if (a.countryIso.isBlank() && r.countryIso.isNotBlank()) {
                        // Guard records created before country binding did not carry the verified
                        // exit country. Never rewrite that assignment while the user is inside the
                        // clone because BlackBox must restart a process to apply a new identity.
                        // Defer the migration until the clone is no longer running.
                        if (!cloneRunning) {
                            val migrated = BlackBoxBridge.setCloneProxy(
                                this, a.auth, a.userId, a.pkg, a.node, r.countryIso
                            )
                            if (migrated.ok && migrated.routeId.isNotBlank()) {
                                a.routeId = migrated.routeId
                                a.countryIso = r.countryIso.lowercase()
                                a.lastRouteCheckAt = 0L
                                persistArmedState()
                                alert(a, "${a.label} - proxy country updated to ${a.countryIso.uppercase()}.")
                                a.testing = false
                                ui.post { updateNotif() }
                                return@execute
                            }
                        }
                    }
                    // A healthy node is not enough: prove the exact running clone still holds the
                    // assignment we armed, has a real proxied exit, and retains DNS/UDP guards.
                    // Mobile/residential nodes may legitimately rotate exit IP inside one session,
                    // so route identity—not byte-for-byte IP pinning—is the isolation proof.
                    val routeDue = SystemClock.elapsedRealtime() - a.lastRouteCheckAt >= ROUTE_VERIFY_SECS * 1000L
                    if (routeDue && cloneRunning) {
                        val route = BlackBoxBridge.verifyRoute(
                            this, a.auth, a.userId, a.pkg, a.expectedExitIp
                        )
                        a.lastRouteCheckAt = SystemClock.elapsedRealtime()
                        if (isConfirmedRouteIdentityViolation(a.routeId, route.routeId, route.state)) {
                            val reason = listOf(route.state, route.error)
                                .filter { it.isNotBlank() }
                                .joinToString(": ")
                                .ifBlank { "route mismatch" }
                            onRouteViolation(a, reason)
                            a.testing = false
                            ui.post { updateNotif() }
                            return@execute
                        } else if (!route.ok || route.exitIp.isBlank()) {
                            // Locale/timezone/sensor checks and third-party exit endpoints can be
                            // temporarily unavailable while the exact assigned route is still
                            // active. They are diagnostics, not proof of a direct-IP or cross-clone
                            // route change. Keep the app open and retry on the next monitor pass.
                            a.routeProbeStrikes++
                            a.lastRouteCheckAt = 0L
                            android.util.Log.w(
                                "ProxyGuardService",
                                "soft route verification failure kept open tag=${a.tag} " +
                                    "route=${route.routeId} state=${route.state}"
                            )
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
                    if (wasBad) alert(a, "✓ ${a.label} — proxy back online (${r.city.ifBlank { r.ip }}). Traffic resumed automatically.")
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

    /**
     * A proxy outage never force-stops or rotates the clone. The native route remains fail-closed,
     * so requests pause instead of falling back to the phone IP. The same app session resumes when
     * the same sticky proxy returns.
     */
    private fun onProxyDead(a: Armed) {
        a.state = "down"
        a.city = ""; a.type = ""; a.ip = ""
        a.nextTestAt = SystemClock.elapsedRealtime() + POLL_SECS * 1000L
        alert(a, "${a.label} — proxy temporarily unreachable. App remains open; network is paused with no direct fallback.")
    }

    private fun onRouteViolation(a: Armed, reason: String) {
        android.util.Log.e(
            "ProxyGuardService",
            "route violation tag=${a.tag} expectedRoute=${a.routeId} reason=$reason"
        )
        BlackBoxBridge.stopClone(this, a.auth, a.userId, a.pkg)
        ARMED.remove(a.tag)
        ARMED_LAST.remove(a.tag)
        persistArmedState()
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
                    "🟡 ${a.label} — proxy recovering; network paused · rechecking in ${secs}s"
                }
                "down" -> "🔴 ${a.label} — proxy unavailable; app network paused, route retained."
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
            .addAction(0, "Stop monitoring", stopAll)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    /** High-priority one-shot heads-up so the user notices an app was closed / came back. */
    private fun alert(a: Armed, msg: String) {
        try {
            val n = NotificationCompat.Builder(this, CHANNEL_ALERT)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("ShieldProxy — route monitor")
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
            nm.createNotificationChannel(NotificationChannel(CHANNEL_ALERT, "Proxy route alerts",
                NotificationManager.IMPORTANCE_HIGH).apply { description = "Proxy paused / recovered / unsafe route" })
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
        private const val FAIL_STRIKES = 3        // tolerate two transient failures; route stays fail-closed
        private const val STATE_FILE = "proxy_guard_state.sec"
        private const val FG_ID = 4801
        private const val CHANNEL = "proxy_guard"
        private const val CHANNEL_ALERT = "proxy_guard_alert"
        const val ACTION_ARM = "com.privacyshield.proxy.GUARD_ARM"
        const val ACTION_DISARM = "com.privacyshield.proxy.GUARD_DISARM"
        const val ACTION_STOP_ALL = "com.privacyshield.proxy.GUARD_STOP_ALL"

        /**
         * Closing a running clone is reserved for proof that its configured route identity was
         * removed or replaced. Geo/locale, sensor and external exit-check failures do not establish
         * that condition and must never interrupt the user's active app session.
         */
        internal fun isConfirmedRouteIdentityViolation(
            expectedRouteId: String,
            observedRouteId: String,
            state: String
        ): Boolean = expectedRouteId.isBlank() ||
            observedRouteId != expectedRouteId ||
            state == "ROUTE_MISMATCH" ||
            state == "CONFIG_MISSING"

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
                "recovering" -> "🟡 Proxy recovering — network paused"
                "down" -> "🔴 Proxy unavailable — network paused"
                else -> "⏳ Checking…"
            }
        }

        fun isArmed(tag: String): Boolean = ARMED.containsKey(tag)
    }
}
