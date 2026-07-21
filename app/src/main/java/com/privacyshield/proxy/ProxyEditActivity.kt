package com.privacyshield.proxy

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.privacyshield.proxy.core.ProxyLibrary
import com.privacyshield.proxy.core.ProxyNode
import com.privacyshield.proxy.core.ProxyTester
import com.privacyshield.proxy.core.SavedProxy
import com.privacyshield.proxy.core.ShareLink

/**
 * Add a proxy — either the simple SOCKS5/HTTP fields, or import a share-link /
 * config for modern protocols (Hysteria2, TUIC, VLESS-Reality, Shadowsocks,
 * VMess, Trojan, WireGuard). Test it, then save to the library.
 */
class ProxyEditActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_NAME = "name"
        const val EXTRA_EDIT_NAME = "editName"
        private val TYPES = listOf("socks5", "http")
    }

    private lateinit var name: EditText
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var user: EditText
    private lateinit var pass: EditText
    private lateinit var type: Spinner
    private lateinit var status: TextView

    // set when a share-link is imported (carries protocol-specific keys)
    private var imported: ProxyNode? = null

    @Volatile private var lastIp = ""
    @Volatile private var lastCity = ""
    private var originalNode: ProxyNode? = null
    @Volatile private var testedNode: ProxyNode? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_proxy_edit)
        title = "Add proxy"

        name = findViewById(R.id.pxName)
        host = findViewById(R.id.pxHost)
        port = findViewById(R.id.pxPort)
        user = findViewById(R.id.pxUser)
        pass = findViewById(R.id.pxPass)
        type = findViewById(R.id.pxType)
        status = findViewById(R.id.pxStatus)
        type.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, TYPES)

        findViewById<Button>(R.id.pxImport).setOnClickListener { importDialog() }
        findViewById<Button>(R.id.pxParse).setOnClickListener { parsePaste() }
        findViewById<Button>(R.id.pxTest).setOnClickListener { runTest() }
        findViewById<Button>(R.id.pxSave).setOnClickListener { save() }
        findViewById<Button>(R.id.pxAssignBlackbox).setOnClickListener { assignToBlackBox() }

        // typing in host clears a prior import (back to manual mode)
        host.setOnFocusChangeListener { _, focused -> if (focused) imported = null }

        intent.getStringExtra(EXTRA_EDIT_NAME)?.let { loadForEdit(it) }
    }

    private fun loadForEdit(editName: String) {
        val sp = ProxyLibrary.load(this).firstOrNull { it.node.name == editName } ?: return
        title = "Edit proxy"
        val n = sp.node
        originalNode = n
        lastIp = sp.lastIp; lastCity = sp.lastCity
        name.setText(n.name)
        name.isEnabled = false // name is the key; rename from the library screen
        host.setText(n.server)
        port.setText(n.port.toString())
        user.setText(n.username)
        pass.setText(n.password)
        if (n.type == "socks5" || n.type == "http") {
            type.setSelection(TYPES.indexOf(n.type).coerceAtLeast(0))
        } else {
            // advanced protocol: keep its node (extraLines) intact
            imported = n
            status.text = "Editing ${n.type.uppercase()} proxy"
        }
    }

    private fun importDialog() {
        val input = EditText(this).apply {
            hint = "ss:// vless:// hysteria2:// tuic:// trojan:// vmess:// or WireGuard .conf"
            setSingleLine(false); minLines = 3
        }
        AlertDialog.Builder(this)
            .setTitle("Import proxy link / config")
            .setView(input)
            .setPositiveButton("Import") { _, _ ->
                val node = ShareLink.parse(input.text.toString())
                if (node == null) {
                    status.text = "✗ Could not parse that link/config"
                } else {
                    imported = node
                    name.setText(node.name)
                    host.setText(node.server)
                    port.setText(node.port.toString())
                    user.setText("")
                    pass.setText(node.password)
                    status.text = "✓ Imported ${node.type.uppercase()} — ${node.server}:${node.port}"
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun parsePaste() {
        imported = null
        val raw = host.text.toString().trim()
        var s = raw.substringAfter("://", raw)
        var u = ""; var p = ""
        if (s.contains("@")) { u = s.substringBefore("@").substringBefore(":"); p = s.substringBefore("@").substringAfter(":", ""); s = s.substringAfter("@") }
        val parts = s.split(":")
        if (parts.size >= 2) {
            host.setText(parts[0]); port.setText(parts[1].filter { it.isDigit() })
            if (parts.size >= 4 && u.isEmpty()) { u = parts[2]; p = parts[3] }
        }
        if (u.isNotEmpty()) user.setText(u)
        if (p.isNotEmpty()) pass.setText(p)
    }

    private fun currentNode(): ProxyNode {
        val nm = name.text.toString().trim().ifBlank { "Proxy" }
        imported?.let { return it.copy(name = nm) }
        return ProxyNode(
            name = nm,
            type = TYPES[type.selectedItemPosition],
            server = host.text.toString().trim(),
            port = port.text.toString().toIntOrNull() ?: 0,
            username = user.text.toString().trim(),
            password = pass.text.toString()
        )
    }

    private fun runTest() {
        val node = currentNode()
        if (!node.isValid()) { status.text = "Enter host + port first"; return }
        status.text = "Testing… (mobile proxies can take a few seconds)"
        Thread {
            val r = ProxyTester.test(node)
            runOnUiThread {
                when {
                    r.ok && r.reachableOnly -> {
                        lastIp = ""; lastCity = ""
                        testedNode = node
                        status.text = "✓ ${node.type.uppercase()} server reachable — start the list, then Check IP for the exit IP"
                    }
                    r.ok -> {
                        lastIp = r.ip; lastCity = r.city
                        testedNode = node
                        status.text = "✓ Works — exit ${r.ip}" +
                                (if (r.city.isNotBlank()) " (${r.city})" else "") +
                                (if (r.type.isNotBlank()) "\n${r.type}" else "")
                    }
                    else -> { lastIp = ""; lastCity = ""; testedNode = null; status.text = "✗ Failed: ${r.error}" }
                }
            }
        }.start()
    }

    private fun save() {
        val node = currentNode()
        if (!node.isValid()) { status.text = "Enter host + port first"; return }
        val resultStillMatches = node == originalNode || node == testedNode
        ProxyLibrary.upsert(
            this,
            SavedProxy(node, if (resultStillMatches) lastIp else "", if (resultStillMatches) lastCity else "")
        )
        setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_NAME, node.name))
        finish()
    }

    /**
     * Query BlackBox's bridge for its clones (each User + app) and assign THIS proxy to
     * the one the user picks — routing happens inside BlackBox (per-clone), which the
     * external VPN can't do because all clones share one Android UID.
     */
    private fun assignToBlackBox() {
        val node = currentNode()
        if (!node.isValid()) { status.text = "Enter host + port first"; return }

        val authorities = com.privacyshield.proxy.core.BlackBoxBridge.installedAuthorities(this)
        if (authorities.isEmpty()) { status.text = "✗ No BlackBox variant found. Install/open one first."; return }
        // item = (authority, userId, realpkg, label)
        val items = ArrayList<com.privacyshield.proxy.core.BbClone>()
        for (auth in authorities) {
            val base = com.privacyshield.proxy.core.BlackBoxBridge.baseFor(auth)
            try {
                contentResolver.query(android.net.Uri.withAppendedPath(base, "apps"), null, null, null, null)?.use { c ->
                    while (c.moveToNext()) items.add(
                        com.privacyshield.proxy.core.BbClone(auth, c.getInt(0), c.getString(1), c.getString(2)))
                }
            } catch (_: Exception) { }
        }
        if (items.isEmpty()) {
            status.text = "No BlackBox clones found — add apps in a BlackBox variant first."
            return
        }

        val labels = items.map {
            "${com.privacyshield.proxy.core.BlackBoxBridge.variantName(it.authority)} · User ${it.userId} · ${it.label}"
        }.toTypedArray()
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Route which app through '${node.name}'?")
            .setItems(labels) { _, which ->
                val item = items[which]
                val extras = android.os.Bundle().apply {
                    putInt("userId", item.userId)
                    putString("pkg", item.pkg)   // per-app proxy so apps in the same User don't collide
                    putString("type", node.type)
                    putString("server", node.server)
                    putInt("port", node.port)
                    putString("username", node.username)
                    putString("password", node.password)
                }
                val res = try {
                    contentResolver.call(com.privacyshield.proxy.core.BlackBoxBridge.baseFor(item.authority), "setProxy", null, extras)
                } catch (e: Exception) { null }
                if (res?.getBoolean("ok") == true) {
                    ProxyLibrary.upsert(this, SavedProxy(node, lastIp, lastCity)) // remember it too
                    val v = com.privacyshield.proxy.core.BlackBoxBridge.variantName(item.authority)
                    status.text = "✓ '${item.label}' ($v User ${item.userId}) → ${node.name}. Reopen that app to apply."
                } else {
                    status.text = "✗ Failed to assign (${res?.getString("err") ?: "no response"})"
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
