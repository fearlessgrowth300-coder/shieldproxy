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
    private data class PendingClone(
        val tag: String,
        val authority: String,
        val userId: Int,
        val pkg: String,
        val node: com.privacyshield.proxy.core.ProxyNode
    )
    private data class PendingClear(
        val tag: String,
        val authority: String,
        val userId: Int,
        val pkg: String
    )

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
            if (valid.isEmpty()) {
                if (!clearAndDeleteEmptyProfile()) toast("Add a proxy and pick its apps")
                return
            }
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

    /** Removing the last route means "use the real phone network". Clear BlackBox first so an
     * invisible encrypted assignment cannot survive after the ShieldProxy card disappears. */
    private fun clearAndDeleteEmptyProfile(): Boolean {
        val id = profileId ?: return false
        val profile = ProfileStore.get(this, id) ?: return false
        val errors = profile.config.bbMap.keys.mapNotNull { tag ->
            val parts = tag.split(":", limit = 4)
            val authority = parts.getOrNull(1)
            val userId = parts.getOrNull(2)?.toIntOrNull()
            val pkg = parts.getOrNull(3)
            if (authority == null || userId == null || pkg == null) {
                "${AppList.labelFor(this, tag)}: invalid clone identifier"
            } else {
                val result = com.privacyshield.proxy.core.BlackBoxBridge.clearCloneProxy(
                    this, authority, userId, pkg
                )
                if (result.ok) {
                    ProxyGuardService.disarm(this, tag)
                    null
                } else {
                    "${AppList.labelFor(this, tag)}: " +
                        result.error.ifBlank { result.state.ifBlank { "BlackBox could not clear the route" } }
                }
            }
        }
        if (errors.isNotEmpty()) {
            showSaveFailure("Proxy not removed", errors)
            return true
        }
        ProfileStore.delete(this, id)
        toast("Proxy removed — this clone now uses the phone network")
        finish()
        return true
    }

    /** Run the isolation rules; commit immediately if clean, else require move/correction. */
    private fun validateThenCommit(name: String, valid: List<Route>) {
        val intendedBb = LinkedHashMap<String, String>()  // clone tag -> node name
        for (r in valid) r.apps.forEach { pkg -> if (pkg.startsWith("bb:")) intendedBb[pkg] = r.proxy!! }
        val tags = intendedBb.keys.toList()

        val conflicts = com.privacyshield.proxy.core.AssignmentRules.crossProfileConflicts(this, profileId, tags)
        val coloc = com.privacyshield.proxy.core.AssignmentRules
            .sensitiveCoLocations(this, profileId, tags)
        val gms = com.privacyshield.proxy.core.AssignmentRules
            .gmsProxyInconsistencies(this, profileId, intendedBb)
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
        if (hardBlock) {
            // These are security boundaries, not advisory warnings. Require the user to separate
            // the virtual users or make the shared-GMS route consistent before saving.
            b.setPositiveButton("OK", null)
        } else if (conflicts.isNotEmpty()) {
            b.setPositiveButton("Move here") { _, _ ->
                com.privacyshield.proxy.core.AssignmentRules.moveTagsHere(this, profileId, conflicts.map { it.tag })
                commitPerApp(name, valid)
            }
        }
        b.show()
    }

    /** Build, validate, apply, then persist. A rejected clone never becomes a saved claim. */
    private fun commitPerApp(name: String, valid: List<Route>) {
        val lib = ProxyLibrary.load(this)
        val previousCloneTags = profileId
            ?.let { ProfileStore.get(this, it) }
            ?.config?.bbMap?.keys?.toSet()
            .orEmpty()
        val cfg = RoutingConfig().apply { processMatchMode = ProcessMatchMode.ALWAYS }
        val added = HashSet<String>()
        val pendingClones = ArrayList<PendingClone>()
        val localErrors = ArrayList<String>()
        for (route in valid) {
            val node = lib.firstOrNull { it.node.name == route.proxy }?.node
            if (node == null || !node.isValid()) {
                localErrors.add("${route.proxy ?: "Unknown proxy"}: proxy is missing or invalid")
                continue
            }
            route.apps.forEach { tag ->
                if (tag.startsWith("bb:")) {
                    cfg.bbMap[tag] = node.name
                    if (added.add(node.name)) cfg.nodes.add(node)
                    val parts = tag.split(":", limit = 4)
                    val authority = parts.getOrNull(1)
                    val userId = parts.getOrNull(2)?.toIntOrNull()
                    val pkg = parts.getOrNull(3)
                    if (authority != null && userId != null && pkg != null) {
                        pendingClones.add(PendingClone(tag, authority, userId, pkg, node))
                    } else {
                        localErrors.add("${AppList.labelFor(this, tag)}: invalid clone identifier")
                    }
                } else {
                    if (added.add(node.name)) cfg.nodes.add(node)
                    cfg.appMap[tag] = node.name
                }
            }
        }
        cfg.finalTarget = "DIRECT"

        if (localErrors.isNotEmpty()) {
            showSaveFailure("List not saved", localErrors)
            return
        }

        // Phase 1 is read-only. Validate all clones before any credential file is changed.
        val preflightErrors = pendingClones.mapNotNull { pending ->
            val result = com.privacyshield.proxy.core.BlackBoxBridge.canSetCloneProxy(
                this, pending.authority, pending.userId, pending.pkg, pending.node
            )
            if (result.ok) null else "${AppList.labelFor(this, pending.tag)}: " +
                result.error.ifBlank { result.state.ifBlank { "BlackBox rejected the assignment" } }
        }
        if (preflightErrors.isNotEmpty()) {
            showSaveFailure("List not saved", preflightErrors)
            return
        }

        // Phase 2 applies only the already-validated routes. A runtime bridge/storage failure still
        // prevents ProfileStore from claiming an assignment BlackBox did not acknowledge.
        val commitErrors = pendingClones.mapNotNull { pending ->
            val result = com.privacyshield.proxy.core.BlackBoxBridge.setCloneProxy(
                this, pending.authority, pending.userId, pending.pkg, pending.node
            )
            if (result.ok) null else "${AppList.labelFor(this, pending.tag)}: " +
                result.error.ifBlank { result.state.ifBlank { "BlackBox could not commit the assignment" } }
        }
        if (commitErrors.isNotEmpty()) {
            showSaveFailure(
                "List not saved",
                commitErrors,
                "Some validated routes may already have reached BlackBox. Fix the error and Save again; protected clones remain fail-closed."
            )
            return
        }
        // setProxy stops the old guest process. Its old monitor must stop with it; otherwise a
        // later guard tick can report/close this tag using the previous route ID even though the
        // newly saved assignment has not been launched yet.
        pendingClones.forEach { ProxyGuardService.disarm(this, it.tag) }

        // New assignments are live and verified by BlackBox. Now remove clone routes that this
        // edit deleted or moved to another virtual user. Without this phase, the old encrypted
        // route and its shared-GMS copy remain active even though Shield no longer displays them.
        val removedClones = (previousCloneTags - cfg.bbMap.keys).mapNotNull { tag ->
            val parts = tag.split(":", limit = 4)
            val authority = parts.getOrNull(1)
            val userId = parts.getOrNull(2)?.toIntOrNull()
            val pkg = parts.getOrNull(3)
            if (authority != null && userId != null && pkg != null) {
                PendingClear(tag, authority, userId, pkg)
            } else null
        }
        val clearErrors = removedClones.mapNotNull { pending ->
            val result = com.privacyshield.proxy.core.BlackBoxBridge.clearCloneProxy(
                this, pending.authority, pending.userId, pending.pkg
            )
            if (result.ok) {
                ProxyGuardService.disarm(this, pending.tag)
                null
            } else "${AppList.labelFor(this, pending.tag)}: " +
                result.error.ifBlank { result.state.ifBlank { "BlackBox could not clear the old assignment" } }
        }
        if (clearErrors.isNotEmpty()) {
            showSaveFailure(
                "List not saved",
                clearErrors,
                "New routes were applied, but an old BlackBox route could not be removed. Protected clones remain fail-closed; fix the connection and Save again."
            )
            return
        }

        val id = profileId ?: ProfileStore.newId(ProfileStore.load(this).size + name.hashCode())
        val profile = Profile(id, name, cfg)
        val claimedTags = ProfileStore.load(this)
            .filter { it.id != id }
            .flatMapTo(LinkedHashSet()) { it.config.bbMap.keys }
            .apply { addAll(cfg.bbMap.keys) }
        val unusedRoutes = com.privacyshield.proxy.core.BlackBoxBridge.configuredRoutes(this)
            .filter { it.tag !in claimedTags }
        if (unusedRoutes.isNotEmpty()) {
            val labels = unusedRoutes.take(8).joinToString("\n") {
                " • ${AppList.labelFor(this, it.tag)}"
            } + if (unusedRoutes.size > 8) "\n • +${unusedRoutes.size - 8} more" else ""
            AlertDialog.Builder(this)
                .setTitle("Remove unused clone routes?")
                .setMessage(
                    "$labels\n\nThese routes are not used by any saved list. They may be leftovers from a moved/deleted clone or direct assignments you want to keep."
                )
                .setPositiveButton("Remove and save") { _, _ ->
                    val errors = unusedRoutes.mapNotNull { route ->
                        val result = com.privacyshield.proxy.core.BlackBoxBridge.clearCloneProxy(
                            this, route.authority, route.userId, route.pkg
                        )
                        if (result.ok) {
                            ProxyGuardService.disarm(this, route.tag)
                            null
                        } else "${AppList.labelFor(this, route.tag)}: " +
                            result.error.ifBlank { result.state.ifBlank { "BlackBox could not clear the route" } }
                    }
                    if (errors.isNotEmpty()) {
                        showSaveFailure("List not saved", errors)
                    } else {
                        persistProfile(profile, pendingClones.size)
                    }
                }
                .setNegativeButton("Keep and save") { _, _ ->
                    persistProfile(profile, pendingClones.size)
                }
                .setNeutralButton("Cancel", null)
                .show()
            return
        }
        persistProfile(profile, pendingClones.size)
    }

    private fun persistProfile(profile: Profile, cloneCount: Int) {
        ProfileStore.upsert(this, profile)
        val message = if (cloneCount > 0) {
            "Saved ✓ $cloneCount clone(s) routed. Reopen them in their app to apply."
        } else "Saved ✓"
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    private fun showSaveFailure(title: String, errors: List<String>, note: String? = null) {
        val distinct = errors.distinct()
        val body = buildString {
            append(distinct.take(6).joinToString("\n\n"))
            if (distinct.size > 6) append("\n\n+${distinct.size - 6} more")
            if (!note.isNullOrBlank()) append("\n\n").append(note)
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(body)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
}
