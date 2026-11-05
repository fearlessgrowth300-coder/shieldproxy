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

    /**
     * Always keep these packages out of the VPN, including when clone routes exist.
     *
     * Commit 296d25b captured them whenever a clone route was saved so a missed hook
     * could be UID-rejected inside the tunnel. That also captured their DNS. Strict
     * Private DNS (Android 9+) then failed over the VPN (`PRIVATE_DNS_BROKEN`) and
     * every in-clone exit check died before it reached the proxy. Loopback to the
     * per-clone listener does not need the container to be inside the TUN.
     * The exit check still refuses to open the app unless the guest's observed IP
     * is the proxy's, which is the fail-closed path for a hook that misses.
     */
    fun packagesExcludedFromVpn(): List<String> = CONTAINER_PACKAGES

    /**
     * Strict Private DNS (Android 9+ hostname mode) does its lookups as DNS-over-TLS.
     * Once the container is inside this VPN, that check is marked PRIVATE_DNS_BROKEN
     * and the guest cannot resolve the exit-check hosts. Outside the VPN, the same
     * strict resolver keeps working, and the hook still dials 127.0.0.1.
     */
    fun inCloneExitCheckCanResolve(containerCapturedByVpn: Boolean, privateDnsStrict: Boolean): Boolean {
        if (containerCapturedByVpn && privateDnsStrict) return false
        return true
    }

    const val PORT_BASE = 20000
    const val PORT_SPAN = 8000

    fun tag(authority: String, userId: Int, pkg: String) = "bb:$authority:$userId:$pkg"

    /** One listener shared by every package in a Blackbox user, including Play Store and GMS. */
    fun userTag(authority: String, userId: Int) = "bb:$authority:$userId:*"

    fun listenerName(port: Int) = "bbp$port"

    fun stablePort(tag: String): Int = PORT_BASE + (stableHash(tag) % PORT_SPAN)

    fun portForUser(authority: String, userId: Int): Int = stablePort(userTag(authority, userId))

    /** User listeners keep [stablePort]. Package listeners move aside when those ports collide. */
    fun portsFor(tags: Map<String, String>): Map<String, Int> {
        val users = tags.keys.filter { it.endsWith(":*") }.sorted()
        val used = HashSet<Int>()
        val reserved = LinkedHashMap<String, Int>()
        for (tag in users) {
            var port = stablePort(tag)
            var spins = 0
            while (!used.add(port)) {
                port = PORT_BASE + ((port - PORT_BASE + 1) % PORT_SPAN)
                if (++spins > PORT_SPAN) error("No free clone listener port")
            }
            reserved[tag] = port
        }
        return assignPorts(tags.keys, reserved)
    }

    /** Stable across process restarts. Adding a new tag does not move an existing port. */
    fun assignPorts(tags: Collection<String>, reserved: Map<String, Int> = emptyMap()): Map<String, Int> {
        val used = HashSet<Int>()
        val out = LinkedHashMap<String, Int>()
        for ((tag, port) in reserved) {
            used.add(port)
            out[tag] = port
        }
        for (tag in tags.distinct().sorted()) {
            if (tag in out) continue
            var port = stablePort(tag)
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
        val users = userListeners(bbMap).filter { (_, node) -> nodeExists(node) }
        if (rows.isEmpty() && users.isEmpty()) return
        val ports = portsFor(rows + users)
        sb.append("listeners:\n")
        for ((tag, node) in rows) {
            writeListener(sb, ports.getValue(tag), tag, node)
        }
        for ((tag, node) in users) {
            writeListener(sb, ports.getValue(tag), tag, node)
        }
    }

    /**
     * Packages in one Blackbox user share a node, so they share one listener.
     * A user whose saved packages name two nodes is omitted; that conflict is a scan failure.
     */
    fun userListeners(bbMap: Map<String, String>): Map<String, String> {
        val nodes = LinkedHashMap<String, MutableSet<String>>()
        for ((tag, node) in bbMap) {
            val parsed = AssignmentRules.parse(tag) ?: continue
            nodes.getOrPut(userTag(parsed.authority, parsed.userId)) { LinkedHashSet() }.add(node)
        }
        val out = LinkedHashMap<String, String>()
        for ((tag, names) in nodes) {
            if (names.size == 1) out[tag] = names.single()
        }
        return out
    }

    private fun writeListener(sb: StringBuilder, port: Int, tag: String, node: String) {
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

    /**
     * `IN-NAME` is first so a SOCKS inbound is pinned to its node even if `proxy:` is ignored.
     * The container UID reject is the leak guard for packets that hit the TUN instead.
     */
    fun appendRules(sb: StringBuilder, bbMap: Map<String, String>, uidOf: ((String) -> Int?)?) {
        if (bbMap.isEmpty()) return
        val users = userListeners(bbMap)
        val ports = portsFor(bbMap + users)
        for ((tag, node) in bbMap) {
            val port = ports[tag] ?: continue
            sb.append("  - IN-NAME,").append(listenerName(port)).append(",").append(node).append("\n")
        }
        for ((tag, node) in users) {
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
