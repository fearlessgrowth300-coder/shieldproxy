package com.privacyshield.proxy.core

import java.security.MessageDigest

/**
 * One local SOCKS inbound per Blackbox clone.
 *
 * Every clone inside a container shares that container's Android UID, so a UID rule cannot
 * tell route 1 from route 2. Each clone gets a stable loopback port. Mihomo pins that
 * inbound to the clone's node (`proxy:`) and an `IN-NAME` rule names the same binding.
 * Traffic from the container UID that still arrives on the TUN did not use its port and is
 * rejected, so a missed hook cannot fall out onto the phone network.
 *
 * The hook that must dial these ports lives in the Blackbox repo. See
 * docs/BLACKBOX-CONNECT-HOOK-CONTRACT.md.
 */
object CloneListeners {
    val CONTAINER_PACKAGES = listOf(
        "top.niunaijun.blackbox",
        "com.novspace.box",
        "app.cloudvault.multi",
        "io.prismhub.clone"
    )

    const val PORT_BASE = 20000
    const val PORT_SPAN = 8000

    fun tag(authority: String, userId: Int, pkg: String) = "bb:$authority:$userId:$pkg"

    fun listenerName(port: Int) = "bbp$port"

    /** Stable across process restarts. Adding a new tag does not move an existing port. */
    fun assignPorts(tags: Collection<String>): Map<String, Int> {
        val used = HashSet<Int>()
        val out = LinkedHashMap<String, Int>()
        for (tag in tags.distinct().sorted()) {
            var port = PORT_BASE + (stableHash(tag) % PORT_SPAN)
            var spins = 0
            while (!used.add(port)) {
                port = PORT_BASE + ((port - PORT_BASE + 1) % PORT_SPAN)
                if (++spins > PORT_SPAN) error("No free clone listener port")
            }
            out[tag] = port
        }
        return out
    }

    fun portFor(authority: String, userId: Int, pkg: String): Int =
        assignPorts(listOf(tag(authority, userId, pkg))).values.single()

    fun socksUser(tag: String) = "sp"

    fun socksPassword(tag: String): String =
        sha256("socks:$tag").take(12).joinToString("") { "%02x".format(it) }

    fun appendListeners(
        sb: StringBuilder,
        bbMap: Map<String, String>,
        nodeExists: (String) -> Boolean
    ) {
        val rows = bbMap.filter { (_, node) -> nodeExists(node) }
        if (rows.isEmpty()) return
        val ports = assignPorts(rows.keys)
        sb.append("listeners:\n")
        for ((tag, node) in rows) {
            val port = ports.getValue(tag)
            sb.append("  - name: ").append(ProxyNode.quote(listenerName(port))).append("\n")
            sb.append("    type: socks\n")
            sb.append("    listen: 127.0.0.1\n")
            sb.append("    port: ").append(port).append("\n")
            sb.append("    udp: true\n")
            sb.append("    proxy: ").append(ProxyNode.quote(node)).append("\n")
            sb.append("    users:\n")
            sb.append("      - username: ").append(ProxyNode.quote(socksUser(tag))).append("\n")
            sb.append("        password: ").append(ProxyNode.quote(socksPassword(tag))).append("\n")
        }
    }

    /**
     * `IN-NAME` is first so a SOCKS inbound is pinned to its node even if `proxy:` is ignored.
     * The container UID reject is the leak guard for packets that hit the TUN instead.
     */
    fun appendRules(sb: StringBuilder, bbMap: Map<String, String>, uidOf: ((String) -> Int?)?) {
        if (bbMap.isEmpty()) return
        val ports = assignPorts(bbMap.keys)
        for ((tag, node) in bbMap) {
            val port = ports[tag] ?: continue
            sb.append("  - IN-NAME,").append(listenerName(port)).append(",").append(node).append("\n")
        }
        for (pkg in CONTAINER_PACKAGES) {
            val uid = uidOf?.invoke(pkg) ?: continue
            if (uid >= 0) sb.append("  - UID,").append(uid).append(",REJECT-DROP\n")
        }
    }

    private fun stableHash(tag: String): Int {
        val digest = sha256(tag)
        return ((digest[0].toInt() and 0xff) shl 8) or (digest[1].toInt() and 0xff)
    }

    private fun sha256(text: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
}
