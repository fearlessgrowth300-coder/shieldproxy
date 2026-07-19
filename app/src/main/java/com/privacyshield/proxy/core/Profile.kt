package com.privacyshield.proxy.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * A named saved setup ("list"): one config (proxies + app→node map + settings).
 * The user picks a profile and hits Start; switching profiles relaunches the
 * engine with that profile's config.
 */
data class Profile(
    val id: String,
    var name: String,
    val config: RoutingConfig
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("config", config.toJson())
    }

    companion object {
        fun fromJson(o: JSONObject): Profile = Profile(
            id = o.optString("id"),
            name = o.optString("name", "Profile"),
            config = o.optJSONObject("config")?.let { RoutingConfig.fromJson(it) } ?: RoutingConfig()
        )
    }
}

/**
 * Persists the list of profiles + which one is active. Activating a profile
 * writes its config to routing.json, which ShieldVpnService/the engine reads.
 */
object ProfileStore {
    private const val FILE = "profiles.json"

    fun load(ctx: Context): MutableList<Profile> {
        if (!SecureFileStore.exists(ctx, FILE)) return mutableListOf()
        val root = JSONObject(SecureFileStore.readText(ctx, FILE)!!)
        val arr = root.optJSONArray("profiles") ?: JSONArray()
        return MutableList(arr.length()) { Profile.fromJson(arr.getJSONObject(it)) }
    }

    fun activeId(ctx: Context): String? {
        if (!SecureFileStore.exists(ctx, FILE)) return null
        return JSONObject(SecureFileStore.readText(ctx, FILE)!!)
            .optString("activeId").ifBlank { null }
    }

    fun saveAll(ctx: Context, profiles: List<Profile>, activeId: String?) {
        val root = JSONObject().apply {
            put("activeId", activeId ?: "")
            put("profiles", JSONArray().apply { profiles.forEach { put(it.toJson()) } })
        }
        SecureFileStore.writeText(ctx, FILE, root.toString(2))
    }

    fun get(ctx: Context, id: String): Profile? = load(ctx).firstOrNull { it.id == id }

    fun upsert(ctx: Context, profile: Profile) {
        val list = load(ctx)
        val idx = list.indexOfFirst { it.id == profile.id }
        if (idx >= 0) list[idx] = profile else list.add(profile)
        saveAll(ctx, list, activeId(ctx))
    }

    fun delete(ctx: Context, id: String) {
        val list = load(ctx).filterNot { it.id == id }
        val active = activeId(ctx)?.takeIf { it != id }
        saveAll(ctx, list, active)
    }

    /** Make [id] active and write its config to the engine's routing.json. */
    fun activate(ctx: Context, id: String) {
        val p = get(ctx, id) ?: return
        saveAll(ctx, load(ctx), id)
        p.config.save(ctx) // writes routing.json read by ShieldVpnService
    }

    fun activeConfig(ctx: Context): RoutingConfig? =
        activeId(ctx)?.let { get(ctx, it)?.config }

    fun newId(seed: Int): String = "p" + System.currentTimeMillis().toString(36) + seed.toString(36)
}
