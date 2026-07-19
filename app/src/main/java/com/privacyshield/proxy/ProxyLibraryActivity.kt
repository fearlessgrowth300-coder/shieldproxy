package com.privacyshield.proxy

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.privacyshield.proxy.core.ProxyLibrary
import com.privacyshield.proxy.core.ProxyTester
import com.privacyshield.proxy.core.SavedProxy

/** Manage saved proxies: edit, rename, re-test, delete, add. */
class ProxyLibraryActivity : AppCompatActivity() {

    private lateinit var rv: RecyclerView
    private lateinit var empty: TextView
    private val adapter = Adapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_proxy_library)
        rv = findViewById(R.id.pxLibRv)
        empty = findViewById(R.id.pxEmpty)
        rv.layoutManager = LinearLayoutManager(this)
        rv.adapter = adapter
        findViewById<Button>(R.id.pxLibAdd).setOnClickListener {
            startActivity(Intent(this, ProxyEditActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        val list = ProxyLibrary.load(this)
        adapter.submit(list)
        empty.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun menuFor(sp: SavedProxy) {
        AlertDialog.Builder(this)
            .setTitle(sp.node.name)
            .setItems(arrayOf("Edit", "Rename", "Re-test", "Delete")) { _, w ->
                when (w) {
                    0 -> edit(sp)
                    1 -> renameDialog(sp)
                    2 -> retest(sp)
                    else -> confirmDelete(sp)
                }
            }.show()
    }

    private fun edit(sp: SavedProxy) {
        startActivity(Intent(this, ProxyEditActivity::class.java)
            .putExtra(ProxyEditActivity.EXTRA_EDIT_NAME, sp.node.name))
    }

    private fun renameDialog(sp: SavedProxy) {
        val input = EditText(this).apply { setText(sp.node.name); setSelection(sp.node.name.length) }
        AlertDialog.Builder(this)
            .setTitle("Rename proxy")
            .setView(input)
            .setPositiveButton("Rename") { _, _ ->
                val newName = input.text.toString().trim()
                if (newName.isBlank()) { toast("Name can't be empty"); return@setPositiveButton }
                if (ProxyLibrary.load(this).any { it.node.name == newName }) { toast("Name already used"); return@setPositiveButton }
                ProxyLibrary.rename(this, sp.node.name, newName)
                refresh()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun retest(sp: SavedProxy) {
        val dialog = AlertDialog.Builder(this)
            .setTitle(sp.node.name).setMessage("Testing…").setPositiveButton("OK", null).create()
        dialog.show()
        Thread {
            val r = ProxyTester.test(sp.node)
            runOnUiThread {
                if (r.ok && r.reachableOnly) {
                    dialog.setMessage("✓ ${sp.node.type.uppercase()} server reachable (start a list to see exit IP)")
                } else if (r.ok) {
                    ProxyLibrary.upsert(this, sp.copy(lastIp = r.ip, lastCity = r.city))
                    dialog.setMessage("✓ Exit ${r.ip}" + if (r.city.isNotBlank()) " (${r.city})" else "")
                    refresh()
                } else dialog.setMessage("✗ ${r.error}")
            }
        }.start()
    }

    private fun confirmDelete(sp: SavedProxy) {
        AlertDialog.Builder(this)
            .setMessage("Delete \"${sp.node.name}\"? Lists already using it keep their own copy.")
            .setPositiveButton("Delete") { _, _ -> ProxyLibrary.delete(this, sp.node.name); refresh() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()

    private inner class Adapter : RecyclerView.Adapter<VH>() {
        private var items: List<SavedProxy> = emptyList()
        fun submit(list: List<SavedProxy>) { items = list; notifyDataSetChanged() }
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
            VH(LayoutInflater.from(parent.context).inflate(R.layout.item_proxy, parent, false))
        override fun getItemCount() = items.size
        override fun onBindViewHolder(h: VH, position: Int) {
            val sp = items[position]
            h.name.text = sp.node.name
            val where = when {
                sp.lastCity.isNotBlank() -> "${sp.lastCity} · ${sp.lastIp}"
                sp.lastIp.isNotBlank() -> sp.lastIp
                else -> "not tested"
            }
            h.detail.text = "${sp.node.type} · ${sp.node.server}:${sp.node.port} · $where"
            h.itemView.setOnClickListener { edit(sp) }
            h.itemView.setOnLongClickListener { menuFor(sp); true }
            h.menu.setOnClickListener { menuFor(sp) }
        }
    }

    private class VH(v: View) : RecyclerView.ViewHolder(v) {
        val name: TextView = v.findViewById(R.id.pxRowName)
        val detail: TextView = v.findViewById(R.id.pxRowDetail)
        val menu: Button = v.findViewById(R.id.pxRowMenu)
    }
}
