package com.privacyshield.proxy.core

import android.content.Context

/**
 * Isolation guarantees for multi-account farming. A wrong proxy/user assignment silently links
 * accounts, so these checks run before a list is saved:
 *
 *  1. A clone (BlackBox user + app) may live in only ONE list. Block silent duplication across
 *     profiles and offer to MOVE the clone here instead of assigning it twice.
 *  2. Each Instagram / WhatsApp account gets its OWN BlackBox user — no two sensitive accounts
 *     sharing one virtual device (= one device fingerprint + one GMS identity).
 *  3. When shared-GMS notifications are on for a user, every clone under that user must use the
 *     SAME proxy node, so push traffic and app traffic exit on the same IP.
 *
 * A BlackBox clone tag is "bb:<authority>:<userId>:<pkg>".
 */
object AssignmentRules {

    /** Instagram + WhatsApp packages (incl. business / lite) that each demand their own user. */
    val SENSITIVE = setOf(
        "com.instagram.android", "com.instagram.lite",
        "com.whatsapp", "com.whatsapp.w4b"
    )

    data class Tag(val raw: String, val authority: String, val userId: Int, val pkg: String) {
        /** Identity of the BlackBox virtual device this clone lives in. */
        val user get() = "$authority:$userId"
    }

    fun parse(tag: String): Tag? {
        if (!tag.startsWith("bb:")) return null
        val p = tag.split(":", limit = 4)
        val auth = p.getOrNull(1)?.takeIf { it.isNotBlank() } ?: return null
        val uid = p.getOrNull(2)?.toIntOrNull() ?: return null
        val pkg = p.getOrNull(3)?.takeIf { it.isNotBlank() } ?: return null
        return Tag(tag, auth, uid, pkg)
    }

    // 1. Cross-profile duplicates ------------------------------------------------

    data class Conflict(val tag: String, val pkg: String, val otherProfileId: String, val otherProfileName: String)

    /** For each of [tags], the OTHER saved profile that already owns it (empty if none). */
    fun crossProfileConflicts(ctx: Context, thisProfileId: String?, tags: Collection<String>): List<Conflict> {
        val others = ProfileStore.load(ctx).filter { it.id != thisProfileId }
        val out = ArrayList<Conflict>()
        for (tag in tags) {
            val owner = others.firstOrNull { it.config.bbMap.containsKey(tag) } ?: continue
            out.add(Conflict(tag, parse(tag)?.pkg ?: tag, owner.id, owner.name))
        }
        return out
    }

    /** Remove [tags] from every OTHER profile (used when the user chooses "Move here"). */
    fun moveTagsHere(ctx: Context, thisProfileId: String?, tags: Collection<String>) {
        val all = ProfileStore.load(ctx)
        var changed = false
        for (p in all) {
            if (p.id == thisProfileId) continue
            val before = p.config.bbMap.size
            tags.forEach { p.config.bbMap.remove(it) }
            if (p.config.bbMap.size != before) {
                pruneOrphanNodes(p.config)
                changed = true
            }
        }
        if (changed) ProfileStore.saveAll(ctx, all, ProfileStore.activeId(ctx))
    }

    private fun pruneOrphanNodes(cfg: RoutingConfig) {
        val used = (cfg.appMap.values + cfg.bbMap.values + cfg.finalTarget).toHashSet()
        cfg.nodes.retainAll { it.name in used }
    }

    // 2. Sensitive co-location ---------------------------------------------------

    /** BlackBox users ("authority:userId") that would host MORE THAN ONE IG/WhatsApp account. */
    fun sensitiveCoLocations(tags: Collection<String>): List<String> {
        val byUser = HashMap<String, MutableList<String>>()
        for (t in tags.mapNotNull { parse(it) }) {
            if (t.pkg in SENSITIVE) byUser.getOrPut(t.user) { mutableListOf() }.add(t.pkg)
        }
        return byUser.filterValues { it.size > 1 }.keys.toList()
    }

    // 3. GMS proxy consistency ---------------------------------------------------

    data class GmsInconsistency(val user: String, val nodes: Set<String>)

    /** For every shared-GMS user, the set of distinct nodes its clones use — a violation if >1. */
    fun gmsProxyInconsistencies(ctx: Context, bbMap: Map<String, String>): List<GmsInconsistency> {
        val byUser = HashMap<String, MutableSet<String>>()
        for ((tag, node) in bbMap) {
            val t = parse(tag) ?: continue
            if (GmsShareStore.isEnabled(ctx, t.authority, t.userId)) {
                byUser.getOrPut(t.user) { mutableSetOf() }.add(node)
            }
        }
        return byUser.filter { it.value.size > 1 }.map { GmsInconsistency(it.key, it.value) }
    }
}
