package com.privacyshield.proxy

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.materialswitch.MaterialSwitch
import com.privacyshield.proxy.core.AppList
import com.privacyshield.proxy.core.ProcessMatchMode
import com.privacyshield.proxy.core.Profile
import com.privacyshield.proxy.core.ProfileStore
import com.privacyshield.proxy.core.ProxyLibrary
import com.privacyshield.proxy.core.RoutingConfig

/**
 * Create/edit a list. Two modes:
 *  - Route WHOLE phone through one proxy (toggle on).
 *  - Per-app: add one or more proxies, each with its own apps. Different apps
 *    run through different proxies at the same time.
 */
class ProfileEditActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PROFILE_ID = "profileId"
    }

    private class Route(var proxy: String?, val apps: LinkedHashSet<String> = linkedSetOf())

    private lateinit var nameField: EditText
    private lateinit var routeAll: MaterialSwitch
    private lateinit var routeAllBox: LinearLayout
    private lateinit var perAppBox: LinearLayout
    private lateinit var routesContainer: LinearLayout
    private lateinit var allProxyLabel: TextView

    private var profileId: String? = null
    private var allProxy: String? = null
    private val routes = mutableListOf<Route>()

    // which route a proxy/app pick applies to; -1 = whole-phone proxy, -2 = new route
    private var target = -2

    private val chooseProxyResult =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
            r.data?.getStringExtra(ProxyEditActivity.EXTRA_NAME)?.let { applyProxy(it) }
        }
    private val pickAppsResult =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
            r.data?.getStringArrayExtra(AppPickerActivity.EXTRA_SELECTED)?.let { applyApps(it.toList()) }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_profile_edit)

        nameField = findViewById(R.id.profileName)
        routeAll = findViewById(R.id.routeAll)
        routeAllBox = findViewById(R.id.routeAllBox)
        perAppBox = findViewById(R.id.perAppBox)
        routesContainer = findViewById(R.id.routesContainer)
        allProxyLabel = findViewById(R.id.allProxyLabel)

        profileId = intent.getStringExtra(EXTRA_PROFILE_ID)
        loadExisting()

        routeAll.setOnCheckedChangeListener { _, _ -> renderMode() }
        findViewById<Button>(R.id.chooseAllProxy).setOnClickListener { target = -1; chooseProxy() }
        findViewById<Button>(R.id.addRoute).setOnClickListener { target = -2; chooseProxy() }
        findViewById<Button>(R.id.saveProfile).setOnClickListener { save() }

        renderMode(); renderRoutes(); renderAllProxy()
    }

    private fun loadExisting() {
        val p = profileId?.let { ProfileStore.get(this, it) }
        if (p == null) { title = "New list"; return }
        title = "Edit list"
        nameField.setText(p.name)
        val cfg = p.config
        val wholePhone = cfg.appMap.isEmpty() && cfg.finalTarget != "DIRECT" && cfg.nodes.isNotEmpty()
        if (wholePhone) {
            routeAll.isChecked = true
            allProxy = cfg.finalTarget
        } else {
            // group apps by their node — real apps (appMap) AND clone routes (bbMap)
            val byNode = LinkedHashMap<String, Route>()
            for ((pkg, node) in cfg.appMap) {
                byNode.getOrPut(node) { Route(node) }.apps.add(pkg)
            }
            for ((tag, node) in cfg.bbMap) {
                byNode.getOrPut(node) { Route(node) }.apps.add(tag)
            }
            routes.addAll(byNode.values)
        }
    }

    private fun renderMode() {
        val whole = routeAll.isChecked
        routeAllBox.visibility = if (whole) View.VISIBLE else View.GONE
        perAppBox.visibility = if (whole) View.GONE else View.VISIBLE
    }

    private fun renderAllProxy() {
        allProxyLabel.text = proxySummary(allProxy) ?: "No proxy chosen"
    }

    private fun renderRoutes() {
        routesContainer.removeAllViews()
        routes.forEachIndexed { i, route ->
            val v = LayoutInflater.from(this).inflate(R.layout.item_route, routesContainer, false)
            v.findViewById<TextView>(R.id.routeProxy).text = proxySummary(route.proxy) ?: "No proxy"
            v.findViewById<TextView>(R.id.routeApps).text =
                if (route.apps.isEmpty()) "No apps chosen"
                else route.apps.joinToString(", ") { AppList.labelFor(this, it) }
            v.findViewById<Button>(R.id.routePickApps).setOnClickListener {
                target = i
                pickAppsResult.launch(Intent(this, AppPickerActivity::class.java)
                    .putExtra(AppPickerActivity.EXTRA_SELECTED, route.apps.toTypedArray()))
            }
            v.findViewById<Button>(R.id.routeRemove).setOnClickListener {
                routes.removeAt(i); renderRoutes()
            }
            routesContainer.addView(v)
        }
    }

    private fun proxySummary(name: String?): String? {
        if (name == null) return null
        val sp = ProxyLibrary.load(this).firstOrNull { it.node.name == name } ?: return "$name (missing)"
        return if (sp.lastCity.isNotBlank()) "${sp.node.name} • ${sp.lastCity} (${sp.lastIp})" else sp.node.name
    }

    // ---- pick flow ---------------------------------------------------------

    private fun chooseProxy() {
        val lib = ProxyLibrary.load(this)
        val items = lib.map { it.node.name + (if (it.lastCity.isNotBlank()) "  •  ${it.lastCity}" else "") }.toMutableList()
        items.add("➕  Add & test new proxy")
        AlertDialog.Builder(this)
            .setTitle("Choose proxy")
            .setItems(items.toTypedArray()) { _, which ->
                if (which == items.size - 1) chooseProxyResult.launch(Intent(this, ProxyEditActivity::class.java))
                else applyProxy(lib[which].node.name)
            }
            .show()
    }

    private fun applyProxy(name: String) {
        when (target) {
            -1 -> { allProxy = name; renderAllProxy() }
            -2 -> {
                // new route: create it, then immediately pick its apps
                val route = Route(name)
                routes.add(route)
                target = routes.size - 1
                pickAppsResult.launch(Intent(this, AppPickerActivity::class.java))
            }
            else -> { routes.getOrNull(target)?.proxy = name; renderRoutes() }
        }
    }

    private fun applyApps(pkgs: List<String>) {
        routes.getOrNull(target)?.let { it.apps.clear(); it.apps.addAll(pkgs) }
        renderRoutes()
    }

    // ---- save --------------------------------------------------------------

    private fun save() {
        val name = nameField.text.toString().trim()
        if (name.isEmpty()) { toast("Name the list first"); return }
        val lib = ProxyLibrary.load(this)
        val cfg = RoutingConfig().apply { processMatchMode = ProcessMatchMode.ALWAYS }

        if (routeAll.isChecked) {
            val node = lib.firstOrNull { it.node.name == allProxy }?.node
            if (node == null) { toast("Choose a proxy"); return }
            cfg.nodes.add(node)
            cfg.finalTarget = node.name   // route everything through it
        } else {
            val valid = routes.filter { it.proxy != null && it.apps.isNotEmpty() }
            if (valid.isEmpty()) { toast("Add a proxy and pick its apps"); return }
            // Isolation checks (duplicate clone / IG-WA per user / shared-GMS one-proxy) run first;
            // they may prompt before the actual save happens in commitPerApp().
            validateThenCommit(name, valid)
            return
        }

        val id = profileId ?: ProfileStore.newId(ProfileStore.load(this).size + name.hashCode())
        ProfileStore.upsert(this, Profile(id, name, cfg))
        toast("Saved ✓")
        finish()
    }

    /** Run the isolation rules; commit immediately if clean, else prompt (Move / Save anyway). */
    private fun validateThenCommit(name: String, valid: List<Route>) {
        val intendedBb = LinkedHashMap<String, String>()  // clone tag -> node name
        for (r in valid) r.apps.forEach { pkg -> if (pkg.startsWith("bb:")) intendedBb[pkg] = r.proxy!! }
        val tags = intendedBb.keys.toList()

        val conflicts = com.privacyshield.proxy.core.AssignmentRules.crossProfileConflicts(this, profileId, tags)
        val coloc = com.privacyshield.proxy.core.AssignmentRules.sensitiveCoLocations(tags)
        val gms = com.privacyshield.proxy.core.AssignmentRules.gmsProxyInconsistencies(this, intendedBb)
        if (conflicts.isEmpty() && coloc.isEmpty() && gms.isEmpty()) { commitPerApp(name, valid); return }

        val msg = StringBuilder()
        if (conflicts.isNotEmpty()) {
            msg.append("These clones are already assigned to another list:\n")
            conflicts.forEach { msg.append(" • ${AppList.labelFor(this, it.pkg)} → “${it.otherProfileName}”\n") }
            msg.append("\n")
        }
        if (coloc.isNotEmpty()) {
            msg.append("⚠ Two Instagram/WhatsApp accounts would share one BlackBox user (")
                .append(coloc.joinToString()).append("). Each account needs its own user.\n\n")
        }
        if (gms.isNotEmpty()) {
            msg.append("⚠ A user with shared notifications must use ONE proxy: ")
                .append(gms.joinToString { it.user }).append(" would use ")
                .append(gms.sumOf { it.nodes.size }).append(" different proxies.\n\n")
        }
        val hardBlock = coloc.isNotEmpty() || gms.isNotEmpty()
        val b = AlertDialog.Builder(this)
            .setTitle(if (conflicts.isNotEmpty()) "Move clone(s)?" else "Isolation warning")
            .setMessage(msg.toString().trim())
            .setNegativeButton("Cancel", null)
        if (conflicts.isNotEmpty()) {
            b.setPositiveButton("Move here" + if (hardBlock) " & save anyway" else "") { _, _ ->
                com.privacyshield.proxy.core.AssignmentRules.moveTagsHere(this, profileId, conflicts.map { it.tag })
                commitPerApp(name, valid)
            }
        } else {
            b.setPositiveButton("Save anyway") { _, _ -> commitPerApp(name, valid) }
        }
        b.show()
    }

    /** Build the config, push proxies into the container clones, persist, and report. */
    private fun commitPerApp(name: String, valid: List<Route>) {
        val lib = ProxyLibrary.load(this)
        val cfg = RoutingConfig().apply { processMatchMode = ProcessMatchMode.ALWAYS }
        val added = HashSet<String>()
        var bbOk = 0; var bbFail = 0
        for (route in valid) {
            val node = lib.firstOrNull { it.node.name == route.proxy }?.node ?: continue
            route.apps.forEach { pkg ->
                if (pkg.startsWith("bb:")) {
                    // BlackBox clone → remember it in the profile and push the proxy into that
                    // variant via its bridge (routed by the container, not this VPN — clones share
                    // one UID). Tag format: "bb:<authority>:<userId>:<realpkg>".
                    cfg.bbMap[pkg] = node.name
                    // Register the node (not mapped to any app) so "Check IP" can test it. It is NOT
                    // added to appMap, so the VPN never routes real traffic through it.
                    if (added.add(node.name)) cfg.nodes.add(node)
                    val parts = pkg.split(":", limit = 4)
                    val auth = parts.getOrNull(1)
                    val uid = parts.getOrNull(2)?.toIntOrNull()
                    val realPkg = parts.getOrNull(3)
                    if (auth != null && uid != null && assignBlackBox(auth, uid, realPkg, node)) bbOk++ else bbFail++
                } else {
                    if (added.add(node.name)) cfg.nodes.add(node)
                    cfg.appMap[pkg] = node.name
                }
            }
        }
        cfg.finalTarget = "DIRECT"

        // Persist first, THEN report what actually happened (not just "Saved").
        val id = profileId ?: ProfileStore.newId(ProfileStore.load(this).size + name.hashCode())
        ProfileStore.upsert(this, Profile(id, name, cfg))
        val msg = when {
            bbFail > 0 && bbOk > 0 -> "Saved. $bbOk clone(s) routed; $bbFail couldn't be reached — open them in their app once, then Save again."
            bbFail > 0 -> "Saved, but couldn't reach $bbFail clone(s). Open that app (BlackBox/NovSpace/…) once so it registers, then Save again."
            bbOk > 0 -> "Saved ✓ $bbOk clone(s) routed. Reopen them in their app to apply."
            else -> "Saved ✓"
        }
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
        finish()
    }

    /** Write a proxy to a BlackBox clone (User) via the owning variant's bridge.
     *  @return true if the container acknowledged the assignment. */
    private fun assignBlackBox(authority: String, userId: Int, realPkg: String?, node: com.privacyshield.proxy.core.ProxyNode): Boolean {
        return try {
            val base = com.privacyshield.proxy.core.BlackBoxBridge.baseFor(authority)
            val extras = android.os.Bundle().apply {
                putInt("userId", userId)
                if (realPkg != null) putString("pkg", realPkg)   // per-app proxy (else legacy per-user)
                putString("type", node.type)
                putString("server", node.server)
                putInt("port", node.port)
                putString("username", node.username)
                putString("password", node.password)
            }
            val res = contentResolver.call(base, "setProxy", null, extras)
            res?.getBoolean("ok") == true
        } catch (_: Exception) {
            false
        }
    }

    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
}
