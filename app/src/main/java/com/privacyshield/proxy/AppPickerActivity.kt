package com.privacyshield.proxy

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.privacyshield.proxy.core.AppInfo
import com.privacyshield.proxy.core.AppList

/**
 * Visual app picker: tap apps to select them. Returns the selected package
 * names as a String[] extra ("packages"). Pre-selects any passed in.
 */
class AppPickerActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_SELECTED = "packages"
    }

    private val selected = linkedSetOf<String>()
    private var all: List<AppInfo> = emptyList()
    private lateinit var adapter: Adapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_picker)
        title = "Pick apps"

        intent.getStringArrayExtra(EXTRA_SELECTED)?.let { selected.addAll(it) }

        val rv = findViewById<RecyclerView>(R.id.appRv)
        rv.layoutManager = LinearLayoutManager(this)
        adapter = Adapter()
        rv.adapter = adapter

        val search = findViewById<EditText>(R.id.search)
        search.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) = adapter.filter(s?.toString() ?: "")
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })

        findViewById<View>(R.id.done).setOnClickListener {
            setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_SELECTED, selected.toTypedArray()))
            finish()
        }

        // load apps off the main thread
        val loading = findViewById<TextView>(R.id.loading)
        Thread {
            // BlackBox clones first (each User+app), then the real phone apps.
            val bb = loadBlackBoxApps()
            val apps = AppList.installed(this)
            runOnUiThread {
                all = bb + apps
                // A restored profile may still contain a clone tag whose BlackBox user was
                // deleted or whose app was moved to another user. Keeping that invisible value
                // in `selected` makes the editor silently save both the stale and replacement
                // clone. Prune only unavailable BlackBox tags; ordinary phone-app selections are
                // left untouched because package visibility can be temporarily restricted.
                val availableClones = bb.mapTo(HashSet()) { it.packageName }
                val removedStaleClone = selected.removeAll {
                    it.startsWith("bb:") && it !in availableClones
                }
                loading.visibility = View.GONE
                adapter.filter("")
                if (removedStaleClone) {
                    android.widget.Toast.makeText(
                        this,
                        "Removed an unavailable BlackBox clone. Choose its current user.",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                }
            }
        }.start()
    }

    /**
     * Ask BlackBox's bridge for its clones and show them in the same picker. A clone's
     * package is tagged "bb:<userId>:<realpkg>" so ProfileEditActivity can route it via
     * the bridge (inside BlackBox) instead of the VPN. Icons are loaded from the real
     * phone's PackageManager (IG/WhatsApp are installed there too).
     */
    private fun loadBlackBoxApps(): List<AppInfo> {
        val out = ArrayList<AppInfo>()
        // Aggregate clones from EVERY installed BlackBox variant, tagging each with its source
        // authority so the proxy is later assigned to the right variant's bridge.
        for (auth in com.privacyshield.proxy.core.BlackBoxBridge.installedAuthorities(this)) {
            try {
                val base = com.privacyshield.proxy.core.BlackBoxBridge.baseFor(auth)
                val variant = com.privacyshield.proxy.core.BlackBoxBridge.variantName(auth)
                contentResolver.query(android.net.Uri.withAppendedPath(base, "apps"), null, null, null, null)?.use { c ->
                    while (c.moveToNext()) {
                        val uid = c.getInt(0)
                        val pkg = c.getString(1)
                        val label = c.getString(2)
                        val icon = try { packageManager.getApplicationIcon(pkg) } catch (e: Exception) { null }
                        out.add(AppInfo("bb:$auth:$uid:$pkg", "📦 $variant · User $uid · $label", icon))
                    }
                }
            } catch (_: Exception) {
            }
        }
        return out
    }

    private inner class Adapter : RecyclerView.Adapter<VH>() {
        private var shown: List<AppInfo> = emptyList()

        fun filter(q: String) {
            val query = q.trim().lowercase()
            shown = if (query.isEmpty()) all
            else all.filter { it.label.lowercase().contains(query) || it.packageName.contains(query) }
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false)
            return VH(v)
        }

        override fun getItemCount() = shown.size

        override fun onBindViewHolder(h: VH, position: Int) {
            val app = shown[position]
            h.icon.setImageDrawable(app.icon)
            h.label.text = app.label
            h.pkg.text = app.packageName
            h.check.setOnCheckedChangeListener(null)
            h.check.isChecked = selected.contains(app.packageName)
            val toggle = {
                if (selected.contains(app.packageName)) selected.remove(app.packageName)
                else selected.add(app.packageName)
                h.check.isChecked = selected.contains(app.packageName)
            }
            h.check.setOnClickListener { toggle() }
            h.itemView.setOnClickListener { toggle() }
        }
    }

    private class VH(v: View) : RecyclerView.ViewHolder(v) {
        val icon: ImageView = v.findViewById(R.id.appIcon)
        val label: TextView = v.findViewById(R.id.appLabel)
        val pkg: TextView = v.findViewById(R.id.appPkg)
        val check: CheckBox = v.findViewById(R.id.appCheck)
    }
}
