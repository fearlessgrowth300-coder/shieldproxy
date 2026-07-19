package com.privacyshield.proxy.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** A saved proxy plus the last test result (exit IP + city), if any. */
data class SavedProxy(
    val node: ProxyNode,
    var lastIp: String = "",
    var lastCity: String = ""
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("node", node.toJson())
        put("lastIp", lastIp)
        put("lastCity", lastCity)
    }

    companion object {
        fun fromJson(o: JSONObject) = SavedProxy(
            node = ProxyNode.fromJson(o.getJSONObject("node")),
            lastIp = o.optString("lastIp", ""),
            lastCity = o.optString("lastCity", "")
        )
    }
}

/** Persists the reusable proxy list the user builds up over time. */
object ProxyLibrary {
    private const val FILE = "proxies.json"

    fun load(ctx: Context): MutableList<SavedProxy> {
        if (!SecureFileStore.exists(ctx, FILE)) return mutableListOf()
        val arr = JSONArray(SecureFileStore.readText(ctx, FILE)!!)
        return MutableList(arr.length()) { SavedProxy.fromJson(arr.getJSONObject(it)) }
    }

    fun save(ctx: Context, list: List<SavedProxy>) {
        SecureFileStore.writeText(
            ctx, FILE, JSONArray().apply { list.forEach { put(it.toJson()) } }.toString(2)
        )
    }

    /** Add or replace by node name. */
    fun upsert(ctx: Context, proxy: SavedProxy) {
        val list = load(ctx)
        val idx = list.indexOfFirst { it.node.name == proxy.node.name }
        if (idx >= 0) list[idx] = proxy else list.add(proxy)
        save(ctx, list)
    }

    fun delete(ctx: Context, name: String) {
        save(ctx, load(ctx).filterNot { it.node.name == name })
    }

    /**
     * Rename a saved proxy and propagate the new name into every profile that
     * uses it (node names, app→proxy map, whole-phone target), so existing
     * lists keep working.
     */
    fun rename(ctx: Context, old: String, new: String) {
        if (new.isBlank() || new == old) return
        val lib = load(ctx)
        val idx = lib.indexOfFirst { it.node.name == old }
        if (idx < 0) return
        // avoid name collision
        if (lib.any { it.node.name == new }) return
        lib[idx] = lib[idx].copy(node = lib[idx].node.copy(name = new))
        save(ctx, lib)

        val profiles = ProfileStore.load(ctx)
        var changed = false
        for (p in profiles) {
            val cfg = p.config
            for (i in cfg.nodes.indices) if (cfg.nodes[i].name == old) {
                cfg.nodes[i] = cfg.nodes[i].copy(name = new); changed = true
            }
            for (k in cfg.appMap.keys.toList()) if (cfg.appMap[k] == old) {
                cfg.appMap[k] = new; changed = true
            }
            if (cfg.finalTarget == old) { cfg.finalTarget = new; changed = true }
        }
        if (changed) ProfileStore.saveAll(ctx, profiles, ProfileStore.activeId(ctx))
    }
}
