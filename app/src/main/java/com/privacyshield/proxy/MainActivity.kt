package com.privacyshield.proxy

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.privacyshield.proxy.core.AppList
import com.privacyshield.proxy.core.Profile
import com.privacyshield.proxy.core.ProfileStore
import com.privacyshield.proxy.core.ProxyLibrary
import com.privacyshield.proxy.core.RoutingConfig
import com.privacyshield.proxy.core.SecureFileStore
import com.privacyshield.proxy.core.CloudSync
import com.privacyshield.proxy.core.DriveFolderStore
import com.privacyshield.proxy.core.SupaSync
import com.privacyshield.proxy.core.Supabase
import com.privacyshield.proxy.core.Updater
import com.privacyshield.proxy.core.VaultKeyStore
import java.io.File

/**
 * Home: the list of saved profiles ("lists"). Tap a profile to edit it; tap ▶
 * to make it active and launch the engine. Switching to another profile
 * relaunches the engine with that profile's config.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var rv: RecyclerView
    private lateinit var status: TextView
    private lateinit var accountBackup: Button
    private lateinit var adapter: Adapter
    private var pendingStartId: String? = null
    private var protectedDataError: String? = null
    private var protectedRecoveryStarted = false

    companion object {
        // Only prompt for an update once per app process.
        private var updateChecked = false
    }

    private val driveFolderPicker =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            if (uri != null) {
                try {
                    DriveFolderStore.save(this, uri,
                        VaultKeyStore.ownerHash(this) ?: error("Account recovery is not ready"))
                    handleConnectedDrive()
                } catch (e: Exception) {
                    toast("Could not connect Google Drive: ${e.message}")
                    showDriveRequired()
                }
            } else if (!DriveFolderStore.isConnected(this)) {
                showDriveRequired()
            }
        }

    private val accountSettingsLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode != RESULT_OK) return@registerForActivityResult
            when (result.data?.getStringExtra(AccountSettingsActivity.EXTRA_ACTION)) {
                AccountSettingsActivity.ACTION_BACKUP -> backupNow()
                AccountSettingsActivity.ACTION_RESTORE -> confirmRestore()
                AccountSettingsActivity.ACTION_DRIVE -> toast("Cloud sync uses your account — no Google Drive needed.")
                AccountSettingsActivity.ACTION_LOGOUT -> logoutAccount()
            }
        }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
            if (r.resultCode == RESULT_OK) pendingStartId?.let { launch(it) }
            pendingStartId = null
            refresh()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Auth gate: no account = go sign in / sign up first. The account backs your whole setup up
        // to the cloud so a new phone restores everything.
        if (!Supabase.isSignedIn(this) || !VaultKeyStore.isReady(this)) {
            startActivity(Intent(this, AuthActivity::class.java))
            finish()
            return
        }
        CloudSync.recoverInterruptedRestore(this)
        setContentView(R.layout.activity_main)
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            androidx.core.content.ContextCompat.checkSelfPermission(
                this, android.Manifest.permission.POST_NOTIFICATIONS
            ) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            androidx.core.app.ActivityCompat.requestPermissions(
                this, arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 7301
            )
        }
        status = findViewById(R.id.homeStatus)
        accountBackup = findViewById(R.id.accountBackup)
        accountBackup.setOnClickListener { openAccountSettings() }
        findViewById<Button>(R.id.privacyScan).setOnClickListener {
            startActivity(Intent(this, LeakTestActivity::class.java))
        }
        // Keep the old shortcut as a secondary way to open the same visible account screen.
        status.setOnLongClickListener { openAccountSettings(); true }
        rv = findViewById(R.id.profileRv)
        rv.layoutManager = LinearLayoutManager(this)
        adapter = Adapter()
        rv.adapter = adapter

        // Migrate every legacy sensitive store immediately after authentication. Waiting until a
        // VPN start would leave old proxy credentials on disk indefinitely.
        try {
            ProfileStore.load(this)
            ProxyLibrary.load(this)
            RoutingConfig.load(this)
            File(filesDir, "mihomo/config.yaml").delete()
        } catch (_: Exception) {
            protectedDataError = "Protected proxy data could not be unlocked"
            recoverProtectedDataAsync()
        }

        findViewById<Button>(R.id.newProfile).setOnClickListener {
            startActivity(Intent(this, ProfileEditActivity::class.java))
        }
        findViewById<Button>(R.id.openProxies).setOnClickListener {
            startActivity(Intent(this, ProxyLibraryActivity::class.java))
        }

        // In-app update check (once per app session).
        if (!updateChecked) {
            updateChecked = true
            Updater.checkAsync(this) { showUpdateDialog(it) }
        }
    }

    private fun showUpdateDialog(release: Updater.Release) {
        if (isFinishing) return
        AlertDialog.Builder(this)
            .setTitle("Update available — v${release.versionName}")
            .setMessage(release.notes.ifBlank { "A newer version of ShieldProxy is ready." })
            .setCancelable(false)
            .setPositiveButton("Update now") { _, _ -> startUpdate(release) }
            .setNegativeButton("Later", null)
            .show()
    }

    private fun startUpdate(release: Updater.Release) {
        val progress = AlertDialog.Builder(this)
            .setTitle("Downloading update…")
            .setMessage("0%")
            .setCancelable(false)
            .create()
        progress.show()
        Updater.downloadAndInstall(this, release,
            onProgress = { pct -> if (!isFinishing) progress.setMessage("$pct%") },
            onError = { msg -> if (!isFinishing) { progress.dismiss(); toast("Update failed: $msg") } }
        )
    }

    override fun onPause() {
        super.onPause()
        // Keep the cloud copy current so a re-login always restores the latest setup.
        SupaSync.pushAsync(this)
    }

    override fun onResume() {
        super.onResume()
        if (!Supabase.isSignedIn(this) || !VaultKeyStore.isReady(this)) {
            startActivity(Intent(this, AuthActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP))
            finish()
            return
        }
        refresh()
        // Poll the remote emergency kill switch each time the app comes forward.
        com.privacyshield.proxy.core.RemoteControl.checkAsync(this)
    }

    private fun refresh() {
        try {
            adapter.submit(ProfileStore.load(this), ProfileStore.activeId(this))
        } catch (_: Exception) {
            protectedDataError = "Protected proxy data could not be unlocked"
            adapter.submit(emptyList(), null)
            recoverProtectedDataAsync()
        }
        val on = ShieldVpnService.isRunning(this)
        status.text = when {
            protectedDataError != null -> "Locked · $protectedDataError"
            on -> "Protected · Engine on" + (ProfileStore.activeId(this)?.let { id ->
                ProfileStore.get(this, id)?.let { " · ${it.name}" }
            } ?: "")
            lastError.isNotEmpty() -> "Needs attention · $lastError"
            else -> "Ready · Engine off"
        }
    }

    private fun startProfile(id: String) {
        if (protectedDataError != null) {
            toast(protectedDataError!!)
            return
        }
        pendingStartId = id
        requestIgnoreBatteryOptimizations()
        val prep = VpnService.prepare(this)
        if (prep != null) vpnPermission.launch(prep) else launch(id)
    }

    private fun recoverProtectedDataAsync() {
        if (protectedRecoveryStarted || !Supabase.isSignedIn(this)) return
        protectedRecoveryStarted = true
        val app = applicationContext
        Thread {
            val recovered = runCatching {
                val email = Supabase.email(app) ?: error("Account email is missing")
                SecureFileStore.recoverCompatibleAccountKey(
                    app, email, Supabase.getBackupKeyCandidates(app)
                )
            }.onFailure {
                android.util.Log.w("ShieldKeyRecovery",
                    "Recovery request failed: ${it.javaClass.simpleName}")
            }.getOrDefault(false)
            runOnUiThread {
                protectedRecoveryStarted = false
                if (recovered) {
                    protectedDataError = null
                    refresh()
                    toast("Protected proxy data recovered")
                }
            }
        }.apply { name = "ShieldKeyRecovery" }.start()
    }

    /** Ask Samsung to stop killing the VPN service (Doze/"put app to sleep"). */
    private fun requestIgnoreBatteryOptimizations() {
        try {
            val pm = getSystemService(android.os.PowerManager::class.java)
            if (pm != null && !pm.isIgnoringBatteryOptimizations(packageName)) {
                @android.annotation.SuppressLint("BatteryLife")
                val i = Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(android.net.Uri.parse("package:$packageName"))
                startActivity(i)
            }
        } catch (_: Exception) {
        }
    }

    private fun launch(id: String) {
        lastError = ""
        ProfileStore.activate(this, id) // writes routing.json + marks active
        ContextCompat.startForegroundService(this,
            Intent(this, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_START)
        )
        status.postDelayed({ refresh() }, 900)
    }

    private fun stopEngine() {
        startService(Intent(this, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_STOP))
        status.postDelayed({ refresh() }, 400)
    }

    // ---- profile list ------------------------------------------------------

    private inner class Adapter : RecyclerView.Adapter<VH>() {
        private var items: List<Profile> = emptyList()
        private var activeId: String? = null

        fun submit(list: List<Profile>, active: String?) {
            items = list; activeId = active; notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context).inflate(R.layout.item_profile, parent, false)
            return VH(v)
        }

        override fun getItemCount() = items.size

        override fun onBindViewHolder(h: VH, position: Int) {
            val p = items[position]
            h.name.text = p.name
            val node = p.config.nodes.firstOrNull()
            val sp = node?.let { n -> ProxyLibrary.load(this@MainActivity).firstOrNull { it.node.name == n.name } }
            val proxyText = when {
                node == null -> "no proxy"
                sp?.lastCity?.isNotBlank() == true -> "${node.name} • ${sp.lastCity}"
                else -> node.name
            }
            val allKeys = (p.config.appMap.keys + p.config.bbMap.keys).toList()
            val appNames = allKeys.take(3).joinToString(", ") { AppList.labelFor(this@MainActivity, it) }
            val more = allKeys.size - 3
            // If the proxy guard is watching any clone in this list, show its live status so the
            // user can see "Connected" at a glance without opening the notification shade.
            val guardLine = p.config.bbMap.keys.mapNotNull { ProxyGuardService.statusFor(it) }.firstOrNull()
            h.detail.text = "$proxyText\n$appNames" + (if (more > 0) " +$more more" else "") +
                    (if (guardLine != null) "\n$guardLine" else "")

            // Clone-only lists route through the container (per-clone proxy), NOT this VPN — so they
            // don't need Start and, crucially, don't conflict with each other (Android allows only
            // ONE VPN, but any number of clone lists can run at once). Show "Open apps" for them so
            // starting one never stops another.
            val cloneOnly = p.config.bbMap.isNotEmpty() && p.config.appMap.isEmpty() &&
                    p.config.finalTarget == "DIRECT"
            if (cloneOnly) {
                h.toggle.text = "Open apps"
                h.toggle.setOnClickListener { openAllApps(p) }
            } else {
                val running = ShieldVpnService.isRunning(this@MainActivity) && activeId == p.id
                h.toggle.text = if (running) "Stop route" else "Start route"
                h.toggle.setOnClickListener { if (running) stopEngine() else startProfile(p.id) }
            }
            h.checkIp.setOnClickListener { checkIp(p) }
            h.itemView.setOnClickListener {
                startActivity(Intent(this@MainActivity, ProfileEditActivity::class.java)
                    .putExtra(ProfileEditActivity.EXTRA_PROFILE_ID, p.id))
            }
            h.itemView.setOnLongClickListener {
                AlertDialog.Builder(this@MainActivity)
                    .setTitle(p.name)
                    .setItems(arrayOf("Edit", "Open all apps", "🛑 Turn off proxy guard (close apps)", "🔔 Keep receiving messages", "Delete")) { _, w ->
                        when (w) {
                            0 -> startActivity(Intent(this@MainActivity, ProfileEditActivity::class.java)
                                .putExtra(ProfileEditActivity.EXTRA_PROFILE_ID, p.id))
                            1 -> openAllApps(p)
                            2 -> {
                                p.config.bbMap.keys.forEach { ProxyGuardService.disarm(this@MainActivity, it) }
                                toast("Proxy guard off — clones in “${p.name}” closed.")
                                h.itemView.postDelayed({ refresh() }, 600)
                            }
                            3 -> enableKeepAlive(p)
                            else -> { ProfileStore.delete(this@MainActivity, p.id); refresh() }
                        }
                    }.show()
                true
            }
        }
    }

    private class VH(v: View) : RecyclerView.ViewHolder(v) {
        val name: TextView = v.findViewById(R.id.pfName)
        val detail: TextView = v.findViewById(R.id.pfDetail)
        val toggle: Button = v.findViewById(R.id.pfToggle)
        val checkIp: Button = v.findViewById(R.id.pfCheckIp)
    }

    // ---- Live session monitor ------------------------------------------------
    // Instead of a one-shot Check IP the user has to keep re-tapping, this opens a
    // read-only dialog that re-tests every AUTO_SECS and shows each proxy's exit IP
    // plus a session-age/TTL readout. Health monitoring must never rewrite a sticky
    // session behind a logged-in clone.

    private var monitorHandler: android.os.Handler? = null

    private fun checkIp(p: Profile) {
        val nodes = p.config.nodes.filter { it.isValid() }
        if (nodes.isEmpty()) { AlertDialog.Builder(this).setMessage("This list has no proxy.").show(); return }

        val AUTO_SECS = 20
        val handler = android.os.Handler(mainLooper)
        monitorHandler?.removeCallbacksAndMessages(null)
        monitorHandler = handler

        // Mutable node map (name -> current node) so rotation swaps the live username.
        val live = LinkedHashMap<String, com.privacyshield.proxy.core.ProxyNode>()
        nodes.forEach { live[it.name] = it }
        val strikes = HashMap<String, Int>()          // consecutive failures
        val aliveSince = HashMap<String, Long>()       // elapsedRealtime of first OK / last rotation
        var baseLines = "Starting…"
        val counter = intArrayOf(AUTO_SECS)
        val busy = booleanArrayOf(false)

        val dialog = AlertDialog.Builder(this)
            .setTitle("Session monitor — ${p.name}")
            .setMessage("Testing ${nodes.size} proxy(s)…\n(mobile proxies take a few seconds)")
            .setPositiveButton("Close", null)
            .setCancelable(true)
            .create()
        dialog.setOnDismissListener { handler.removeCallbacksAndMessages(null); monitorHandler = null }
        dialog.show()

        fun ageStr(name: String, node: com.privacyshield.proxy.core.ProxyNode): String {
            val ttl = node.sessionLengthSec()
            val start = aliveSince[name]
            if (start == null && ttl == null) return ""
            val ageMin = if (start != null) ((android.os.SystemClock.elapsedRealtime() - start) / 60000).toInt() else 0
            return when {
                ttl != null && start != null -> " · session ${ageMin}m/${ttl / 60}m"
                ttl != null -> " · TTL ${ttl / 60}m"
                else -> " · session ${ageMin}m"
            }
        }

        lateinit var tick: Runnable
        lateinit var runCheck: () -> Unit

        runCheck = {
            if (!busy[0]) {
                busy[0] = true
                Thread {
                    val results = live.values.map { node ->
                        node to com.privacyshield.proxy.core.ProxyTester.test(node)
                    }
                    for ((node, r) in results) {
                        if (r.ok) {
                            strikes[node.name] = 0
                            aliveSince.getOrPut(node.name) { android.os.SystemClock.elapsedRealtime() }
                        } else if (!r.reachableOnly) {
                            val s = (strikes[node.name] ?: 0) + 1
                            strikes[node.name] = s
                            // Read-only monitor: report the failure. Never mutate the session token
                            // or a running clone's route from a background health check.
                        }
                    }
                    val lines = results.map { (node, r) ->
                        val cur = live[node.name] ?: node
                        val age = ageStr(node.name, cur)
                        when {
                            r.ok && r.reachableOnly -> "• ${node.name}: reachable$age"
                            r.ok -> "✓ ${node.name}: ${r.ip}${if (r.city.isNotBlank()) " (${r.city})" else ""}${if (r.type.isNotBlank()) " · ${r.type}" else ""}$age"
                            else -> "✗ ${node.name}: ${r.error}$age"
                        }
                    }
                    runOnUiThread {
                        baseLines = lines.joinToString("\n")
                        counter[0] = AUTO_SECS
                        busy[0] = false
                        dialog.setMessage("$baseLines\n\nAuto-checking… next in ${counter[0]}s")
                        handler.postDelayed(tick, 1000)
                    }
                }.start()
            }
        }

        tick = Runnable {
            counter[0]--
            if (counter[0] <= 0) {
                if (busy[0]) {
                    handler.postDelayed(tick, 1000)          // a check is still running; wait
                } else {
                    dialog.setMessage("$baseLines\n\nRe-testing…")
                    runCheck()
                }
            } else {
                dialog.setMessage("$baseLines\n\nAuto-checking… next in ${counter[0]}s")
                handler.postDelayed(tick, 1000)
            }
        }

        runCheck()
    }

    /** Automation: launch every app mapped in this list, so all accounts open
     *  at once and each routes through its assigned proxy automatically. */
    private fun openAllApps(p: Profile) {
        val realPkgs = p.config.appMap.keys.toList()
        val clonePlans = p.config.bbMap.map { (tag, nodeName) ->
            Triple(tag, nodeName, p.config.nodes.firstOrNull { it.name == nodeName && it.isValid() })
        }
        if (realPkgs.isEmpty() && clonePlans.isEmpty()) {
            AlertDialog.Builder(this).setMessage("This list has no apps.").show(); return
        }
        val invalidRoutes = clonePlans.filter { it.third == null }.map { it.second }.distinct()
        if (invalidRoutes.isNotEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("Clone route missing - nothing opened")
                .setMessage("These assigned proxies are missing or invalid:\n\n${invalidRoutes.joinToString("\n")}\n\nFix the assignments first so no clone can open directly.")
                .setPositiveButton("OK", null).show()
            return
        }
        // Real phone apps route through OUR VPN, so it must be running for them. Clones route
        // inside their container (not the VPN), so they can launch regardless.
        if (realPkgs.isNotEmpty() && (!ShieldVpnService.isRunning(this) || ProfileStore.activeId(this) != p.id)) {
            AlertDialog.Builder(this)
                .setMessage("Start this list first, then open all apps so the phone apps route correctly.")
                .setPositiveButton("OK", null).show()
            return
        }
        for (pkg in realPkgs) {
            packageManager.getLaunchIntentForPackage(pkg)?.let {
                it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
                try { startActivity(it) } catch (_: Exception) {}
            }
        }
        // Stagger clone launches — launching several container activities in the same instant makes
        // them collide on the launcher task; ~1.2s apart lets each come up cleanly.
        val h = android.os.Handler(android.os.Looper.getMainLooper())
        clonePlans.forEachIndexed { i, (tag, _, node) ->
            h.postDelayed({ launchClone(tag, node, p.name) }, i * 1200L)
        }
        val total = realPkgs.size + clonePlans.size
        android.widget.Toast.makeText(this, "Opening $total app(s)…", android.widget.Toast.LENGTH_SHORT).show()
    }

    /** Turn on background keep-alive for every clone in this list (installs GMS + keeps the
     *  container daemon alive). Honest: helps clones stay alive longer; full push-when-killed
     *  is not guaranteed on a no-root device. */
    private fun enableKeepAlive(p: Profile) {
        val users = HashMap<String, MutableSet<Int>>() // authority -> userIds
        for (tag in p.config.bbMap.keys) {
            val parts = tag.split(":", limit = 4)
            val auth = parts.getOrNull(1) ?: continue
            val uid = parts.getOrNull(2)?.toIntOrNull() ?: continue
            users.getOrPut(auth) { mutableSetOf() }.add(uid)
        }
        if (users.isEmpty()) { toast("No clones in this list"); return }
        Thread {
            var ok = 0
            for ((auth, uids) in users) for (uid in uids) {
                try {
                    val extras = android.os.Bundle().apply { putInt("userId", uid); putBoolean("enabled", true) }
                    val r = contentResolver.call(com.privacyshield.proxy.core.BlackBoxBridge.baseFor(auth), "setKeepAlive", null, extras)
                    if (r?.getBoolean("ok") == true) {
                        ok++
                        // Record that this user shares GMS/push, so AssignmentRules enforces one
                        // consistent proxy for all its clones.
                        com.privacyshield.proxy.core.GmsShareStore.setEnabled(this, auth, uid, true)
                    }
                } catch (_: Exception) {}
            }
            runOnUiThread { toast("Keep-alive on for $ok clone(s). Background push isn't 100% guaranteed on a no-root phone.") }
        }.start()
    }

    private fun toast(m: String) = android.widget.Toast.makeText(this, m, android.widget.Toast.LENGTH_LONG).show()

    /** Account menu (long-press the header): who's signed in, manual sync, log out. */
    private fun showAccountDialog() {
        val email = com.privacyshield.proxy.core.Supabase.email(this) ?: "signed in"
        AlertDialog.Builder(this)
            .setTitle("Account")
            .setMessage("$email\n\nYour proxies and lists back up here automatically. Sign in with this account on another phone to restore everything.")
            .setPositiveButton("Sync now") { _, _ ->
                BackupService.startBackup(this)
                toast("Encrypted backup is running in the notification area")
            }
            .setNeutralButton("Log out") { _, _ ->
                logoutAccount()
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showSecureAccountDialog() {
        val email = Supabase.email(this) ?: "signed in"
        val drive = if (DriveFolderStore.isConnected(this)) "Connected" else "Not connected"
        AlertDialog.Builder(this)
            .setTitle("Account & Backup")
            .setMessage("Signed in: $email\nGoogle Drive: $drive\n\nRestore brings back proxies, lists, assignments, and routing positions.")
            .setItems(arrayOf("Back up now", "Restore everything", "Select/change Google Drive folder", "Log out")) { _, which ->
                when (which) {
                    0 -> if (DriveFolderStore.isConnected(this)) backupNow() else driveFolderPicker.launch(null)
                    1 -> if (DriveFolderStore.isConnected(this)) confirmRestore() else driveFolderPicker.launch(null)
                    2 -> driveFolderPicker.launch(null)
                    3 -> {
                        Supabase.signOut(this)
                        VaultKeyStore.clear(this)
                        startActivity(Intent(this, AuthActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP))
                        finish()
                    }
                }
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showDriveRequired() {
        if (isFinishing || DriveFolderStore.isConnected(this)) return
        AlertDialog.Builder(this)
            .setTitle("Connect Google Drive")
            .setMessage("Choose or create a private folder for encrypted ShieldBox backups. Cloned apps never receive access to this folder or your Google account.")
            .setPositiveButton("Choose folder") { _, _ -> driveFolderPicker.launch(null) }
            .setNeutralButton("Open settings") { _, _ -> openAccountSettings() }
            .setNegativeButton("Later", null)
            .setCancelable(true)
            .show()
    }

    private fun openAccountSettings() {
        accountSettingsLauncher.launch(Intent(this, AccountSettingsActivity::class.java))
    }

    private fun logoutAccount() {
        Supabase.signOut(this)
        VaultKeyStore.clear(this)
        startActivity(Intent(this, AuthActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        finish()
    }

    private fun handleConnectedDrive() {
        refresh()
        toast("Google Drive connected")
        Thread {
            val hasCloud = runCatching { CloudSync.hasBackup(this) }.getOrDefault(false)
            runOnUiThread {
                if (hasCloud) {
                    AlertDialog.Builder(this)
                        .setTitle("Existing backup found")
                        .setMessage("Restore the saved ShieldProxy setup, or replace it with the setup currently on this phone?")
                        .setPositiveButton("Restore") { _, _ -> restoreNow() }
                        .setNegativeButton("Use this phone") { _, _ -> backupNow() }
                        .setCancelable(false)
                        .show()
                } else backupNow()
            }
        }.start()
    }

    private fun backupNow() {
        SupaSync.pushAsync(this)
        toast("Backing up to your account…")
    }

    private fun confirmRestore() {
        AlertDialog.Builder(this)
            .setTitle("Restore ShieldProxy?")
            .setMessage("This replaces the proxy library, saved lists, and routing settings on this phone.")
            .setPositiveButton("Restore") { _, _ -> restoreNow() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun restoreNow() {
        toast("Restoring from your account…")
        Thread {
            val ok = runCatching { SupaSync.pull(this) }.getOrDefault(false)
            runOnUiThread {
                refresh()
                toast(if (ok) "Restored from your account ✓" else "No cloud backup found yet")
            }
        }.start()
    }

    /**
     * Launch a BlackBox-variant clone to the FOREGROUND. Tag: "bb:<authority>:<userId>:<pkg>".
     * We start the variant's exported ShortcutActivity with startActivity (from this foreground
     * Activity) instead of the bridge's launchApp — a bridge call runs in the container's
     * background process, and Android blocks background processes from foregrounding an activity,
     * so the clone would silently start behind ShieldProxy and "never open".
     */
    private fun launchClone(tag: String, node: com.privacyshield.proxy.core.ProxyNode?, listName: String): Boolean {
        // Emergency kill switch: never open a clone while it's armed (locally cached, so it holds
        // even offline). Disarmed from Settings or any of the user's other devices.
        if (com.privacyshield.proxy.core.RemoteControl.isKilled(this)) {
            toast("Emergency kill switch is ON — disarm it in Settings to open clones.")
            return false
        }
        val parts = tag.split(":", limit = 4)
        val auth = parts.getOrNull(1) ?: return false
        val uid = parts.getOrNull(2)?.toIntOrNull() ?: return false
        val pkg = parts.getOrNull(3) ?: return false
        val label = "$listName - ${AppList.labelFor(this, pkg)} (U$uid)"

        // A mapped clone is never allowed to open directly when its node disappeared or became invalid.
        if (node == null || !node.isValid()) {
            showCloneFailure(label, "The assigned proxy is missing or invalid.")
            return false
        }

        toast("Checking exact route for $label...")
        Thread {
            val tested = com.privacyshield.proxy.core.ProxyTester.test(node)
            if (!tested.ok || tested.ip.isBlank()) {
                runOnUiThread {
                    showCloneFailure(label, tested.error.ifBlank { "The proxy exit IP could not be confirmed." })
                }
                return@Thread
            }

            val verified = com.privacyshield.proxy.core.BlackBoxBridge
                .assignAndVerifyRoute(this, auth, uid, pkg, node, tested.ip)
            if (!verified.ok || verified.routeId.isBlank()
                || verified.exitIp.isBlank()) {
                com.privacyshield.proxy.core.BlackBoxBridge.stopClone(this, auth, uid, pkg)
                val reason = verified.error.ifBlank {
                    "Route verification failed (${verified.state.ifBlank { "unknown state" }})."
                }
                runOnUiThread { showCloneFailure(label, reason) }
                return@Thread
            }

            runOnUiThread {
                if (startCloneActivity(auth, uid, pkg)) {
                    toast("Connected and isolated - ${tested.city.ifBlank { tested.ip }}")
                    ProxyGuardService.arm(
                        this, tag, node, label, verified.routeId, verified.exitIp
                    )
                } else {
                    com.privacyshield.proxy.core.BlackBoxBridge.stopClone(this, auth, uid, pkg)
                    showCloneFailure(label, "The verified clone could not be opened.")
                }
            }
        }.start()
        return true
    }

    private fun showCloneFailure(label: String, reason: String) {
        AlertDialog.Builder(this)
            .setTitle("Proxy check failed - app not opened")
            .setMessage("$label\n\n$reason\n\nThe clone was kept closed to prevent a direct-IP or cross-clone leak.")
            .setPositiveButton("OK", null).show()
    }

    @Suppress("unused")
    private fun launchCloneLegacy(tag: String, node: com.privacyshield.proxy.core.ProxyNode?, listName: String): Boolean {
        /* Retained only as commented history while this source tree has mixed legacy encoding.
        val parts = tag.split(":", limit = 4)
        val auth = parts.getOrNull(1) ?: return false
        val uid = parts.getOrNull(2)?.toIntOrNull() ?: return false
        val pkg = parts.getOrNull(3) ?: return false
        val label = "$listName · ${AppList.labelFor(this, pkg)} (U$uid)"

        // No proxy on this list -> nothing to guard, nothing to leak; just open.
        if (node == null || !node.isValid()) return startCloneActivity(auth, uid, pkg)

        // Pre-flight: confirm the proxy is CONNECTED before the app is ever entered, so the user
        // knows it's live — and if it's dead we do NOT open (fail-closed, no real-IP leak).
        toast("Checking proxy for $label…")
        Thread {
            val r = com.privacyshield.proxy.core.ProxyTester.test(node)
            runOnUiThread {
                when {
                    r.ok -> {
                        toast("✓ Connected — ${r.city.ifBlank { r.ip }}${if (r.type.isNotBlank()) " · ${r.type}" else ""}")
                        startCloneActivity(auth, uid, pkg)
                        // Arm the kill-switch: keeps testing this proxy and force-closes the clone the
                        // moment it drops / the session expires (with a recovery countdown).
                        ProxyGuardService.arm(this, tag, node, label)
                    }
                    r.reachableOnly -> {
                        AlertDialog.Builder(this)
                            .setTitle("Proxy reachable, exit unconfirmed")
                            .setMessage("$label\n\nThe proxy answered but its exit IP couldn't be confirmed (network wobble). Open anyway with the kill-switch watching?")
                            .setPositiveButton("Open + guard") { _, _ ->
                                startCloneActivity(auth, uid, pkg)
                                ProxyGuardService.arm(this, tag, node, label)
                            }
                            .setNegativeButton("Cancel", null).show()
                    }
                    else -> {
                        AlertDialog.Builder(this)
                            .setTitle("🔴 Proxy DOWN — not opening")
                            .setMessage("$label\n\nThe proxy is not responding, so the app was NOT opened (this prevents your real IP from leaking).\n\n${r.error}")
                            .setPositiveButton(if (node.hasRotatableSession()) "Rotate & retry" else "Retry") { _, _ ->
                                val fresh = if (node.hasRotatableSession()) node.withNewSession(freshSessionId()) else node
                                launchClone(tag, fresh, listName)
                            }
                            .setNegativeButton("Cancel", null).show()
                    }
                }
            }
        }.start()
        */
        return false
    }

    /** Raw foreground launch of a clone (no proxy check). Split out so guarded and un-guarded
     *  paths share the exact same activity-start. */
    private fun startCloneActivity(auth: String, uid: Int, pkg: String): Boolean {
        return try {
            val variantPkg = auth.removeSuffix(".bridge")   // io.prismhub.clone.bridge -> io.prismhub.clone
            val i = Intent()
                .setClassName(variantPkg, "top.niunaijun.blackboxa.view.main.ShortcutActivity")
                .putExtra("pkg", pkg)
                .putExtra("userId", uid)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
            startActivity(i)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun freshSessionId(): String {
        val n = System.nanoTime()
        val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        val sb = StringBuilder("sp")
        var v = if (n < 0) -n else n
        repeat(10) { sb.append(chars[(v % 36).toInt()]); v /= 36 }
        return sb.toString()
    }
}
