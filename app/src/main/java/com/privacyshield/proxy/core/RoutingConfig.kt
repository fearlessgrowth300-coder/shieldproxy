package com.privacyshield.proxy.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** How aggressively Mihomo matches the originating app (Clash-for-Android parity). */
enum class ProcessMatchMode(val clash: String) {
    STRICT("strict"),   // auto-detect if process matching is possible
    ALWAYS("always"),   // force per-app matching (prevents IP leaks in multi-accounting)
    OFF("off")          // disable process matching
}

/**
 * The whole routing map for the device: proxy nodes, a deterministic
 * app-package -> node assignment, free-form rules, rule-providers, geo
 * settings. Serializes to JSON (persistence) and to a Mihomo config.yaml
 * (what the engine actually runs).
 */
data class RoutingConfig(
    val nodes: MutableList<ProxyNode> = mutableListOf(),
    /** package/process name -> node name (or DIRECT / REJECT). Deterministic. */
    val appMap: LinkedHashMap<String, String> = LinkedHashMap(),
    /**
     * BlackBox clone routes: tag "bb:<authority>:<userId>:<pkg>" -> node name. These do NOT go
     * through this VPN (clones share one UID) — they're pushed into the container via its bridge.
     * Kept in the saved profile so the UI can show them and re-apply them, but never emitted to
     * the Mihomo config.
     */
    val bbMap: LinkedHashMap<String, String> = LinkedHashMap(),
    val rules: MutableList<Rule> = mutableListOf(),
    /** Advanced: raw Clash rule lines emitted verbatim (e.g. AND/OR/NOT, RULE-SET). */
    val rawRules: MutableList<String> = mutableListOf(),
    val providers: MutableList<RuleProvider> = mutableListOf(),
    var processMatchMode: ProcessMatchMode = ProcessMatchMode.ALWAYS,
    var finalTarget: String = "DIRECT",   // catch-all for unmatched traffic
    var logLevel: String = "warning",
    var ipv6: Boolean = false,
    /** When IPv6 is off, REJECT all IPv6 destinations so dual-stack apps can't slip
     *  around the tunnel over v6 and expose the phone's real IP. */
    var blockIpv6WhenOff: Boolean = true,
    /** Drop QUIC (UDP/443) globally. QUIC can bypass a TCP-only proxy; dropping it forces
     *  apps to fall back to TLS-over-TCP, which the proxy DOES carry. No direct fallback. */
    var blockQuic: Boolean = true,
    var memConservative: Boolean = true,   // low-RAM devices
    var geodataMode: Boolean = true,
    var geoAutoUpdate: Boolean = true,
    var geoipUrl: String = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
    var geositeUrl: String = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
    var mmdbUrl: String = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb"
) {

    fun isRunnable(): Boolean =
        nodes.any { it.isValid() } || finalTarget == "DIRECT"

    /** Every package that must be captured by the VPN (per-app allow-list). */
    fun routedPackages(): Set<String> =
        appMap.keys.filter { it.contains(".") }.toSet()

    private fun nodeByName(name: String): ProxyNode? = nodes.firstOrNull { it.name == name }

    /** Whether a rule target can carry UDP. DIRECT can; a REJECT/PASS pseudo-target can't;
     *  a named node depends on its protocol. An unknown node name is treated as UDP-incapable
     *  so we fail safe (block its UDP) rather than let it leak. */
    private fun targetCarriesUdp(target: String): Boolean = when (target) {
        "DIRECT" -> true
        "REJECT", "REJECT-DROP", "PASS" -> false
        else -> nodeByName(target)?.carriesUdp() ?: false
    }

    // ---- Mihomo config.yaml generation -------------------------------------

    /**
     * @param tunFd when non-null, written as `tun.file-descriptor` so Mihomo's
     *   sing-tun listener attaches to the VpnService descriptor instead of
     *   opening its own device.
     */
    fun toClashYaml(
        tunFd: Int? = null,
        uidOf: ((String) -> Int?)? = null,
        serverResolver: ((String) -> String?)? = null
    ): String {
        val sb = StringBuilder()
        sb.append("mixed-port: 7890\n")
        sb.append("allow-lan: false\n")
        sb.append("mode: rule\n")
        sb.append("log-level: ").append(logLevel).append("\n")
        sb.append("ipv6: ").append(ipv6).append("\n")
        sb.append("find-process-mode: ").append(processMatchMode.clash).append("\n")
        // Long-lived / sticky connections: keep TCP alive so mobile-proxy IPs
        // aren't dropped by idle timeouts. tcp-concurrent speeds up dialing.
        sb.append("keep-alive-interval: 30\n")
        sb.append("keep-alive-idle: 600\n")
        sb.append("tcp-concurrent: true\n")
        sb.append("geodata-mode: ").append(geodataMode).append("\n")
        sb.append("geo-auto-update: ").append(geoAutoUpdate).append("\n")
        sb.append("geox-url:\n")
        sb.append("  geoip: ").append(ProxyNode.quote(geoipUrl)).append("\n")
        sb.append("  geosite: ").append(ProxyNode.quote(geositeUrl)).append("\n")
        sb.append("  mmdb: ").append(ProxyNode.quote(mmdbUrl)).append("\n")

        // In-app TUN: the fd is attached by the native bridge at runtime, so we
        // only enable it here. auto-route is off because VpnService owns routing.
        sb.append("tun:\n")
        sb.append("  enable: true\n")
        if (tunFd != null) sb.append("  file-descriptor: ").append(tunFd).append("\n")
        sb.append("  stack: ").append(if (memConservative) "gvisor" else "mixed").append("\n")
        sb.append("  dns-hijack:\n")
        sb.append("    - any:53\n")
        sb.append("  auto-route: false\n")
        // Outbound sockets are protected via VpnService.protect() (the bridge's
        // DefaultSocketHook), which bypasses the tun — so interface auto-detect
        // is unnecessary here.
        sb.append("  auto-detect-interface: false\n")

        sb.append("dns:\n")
        sb.append("  enable: true\n")
        sb.append("  ipv6: ").append(ipv6).append("\n")
        sb.append("  enhanced-mode: fake-ip\n")
        sb.append("  fake-ip-range: 198.18.0.1/16\n")
        // Route target DNS transport by the same rules as the app connection. In whole-phone
        // mode this sends DoH through the selected proxy instead of asking a resolver directly
        // from the phone's real network. Proxy-host bootstrap remains explicitly separate below.
        sb.append("  respect-rules: true\n")
        // Remote-DNS-only hardening: never read the phone's system resolvers or hosts file
        // (those would resolve on the real network = a DNS leak), and keep DoH on HTTP/2
        // (TCP) rather than HTTP/3 (QUIC), consistent with the QUIC block below.
        sb.append("  use-hosts: false\n")
        sb.append("  use-system-hosts: false\n")
        sb.append("  prefer-h3: false\n")
        // Plain-IP bootstrap resolvers so proxy-server hostnames (and the DoH
        // servers) resolve DIRECTLY — avoids the deadlock where resolving the
        // proxy host needs the proxy that isn't up yet.
        sb.append("  default-nameserver:\n")
        sb.append("    - 223.5.5.5\n")
        sb.append("    - 8.8.8.8\n")
        sb.append("  proxy-server-nameserver:\n")
        sb.append("    - 223.5.5.5\n")
        sb.append("    - 8.8.8.8\n")
        sb.append("  nameserver:\n")
        sb.append("    - https://1.1.1.1/dns-query\n")
        sb.append("    - https://8.8.8.8/dns-query\n")

        sb.append("profile:\n")
        sb.append("  store-selected: true\n")

        // Proxies
        sb.append("proxies:\n")
        val valid = nodes.filter { it.isValid() }
        if (valid.isEmpty()) {
            sb.append("  []\n")
        } else {
            for (n in valid) sb.append(n.toClashYaml(serverOverride = serverResolver?.invoke(n.server)))
        }

        // A selector group holding every node (+ DIRECT) for manual/UI selection.
        sb.append("proxy-groups:\n")
        sb.append("  - name: PROXY\n")
        sb.append("    type: select\n")
        sb.append("    proxies:\n")
        for (n in valid) sb.append("      - ").append(ProxyNode.quote(n.name)).append("\n")
        sb.append("      - DIRECT\n")

        // Rule providers
        if (providers.isNotEmpty()) {
            sb.append("rule-providers:\n")
            for (p in providers) sb.append(p.toClashYaml())
        }

        // Rules: per-app map first (highest priority, deterministic), then
        // user rules, then the final catch-all.
        sb.append("rules:\n")
        // (A) LEAK GUARDS — evaluated before any app route, so nothing slips past them.
        // These harden the phone-app (VpnService) path; container clones are enforced
        // separately in the BlackBox bridge.
        //
        // IPv6 kill: when IPv6 is off, drop every IPv6 destination. Otherwise a dual-stack
        // app could reach the internet over v6 around the (v4) tunnel and expose the real IP.
        // no-resolve = match on address without triggering a DNS lookup.
        if (!ipv6 && blockIpv6WhenOff) {
            sb.append("  - IP-CIDR6,::/0,REJECT-DROP,no-resolve\n")
        }
        // QUIC kill: QUIC rides UDP/443 and can bypass a TCP-only proxy. Dropping it makes
        // apps fall back to TLS-over-TCP (which the proxy carries) — never to the real network.
        if (blockQuic) {
            sb.append("  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT-DROP\n")
        }
        // Per-app UDP guard: any app routed to a proxy that CAN'T carry UDP must not emit UDP
        // at all, or it would fail (or leak). Block that app's UDP before its route rule.
        for ((pkg, node) in appMap) {
            if (targetCarriesUdp(node)) continue
            val uid = uidOf?.invoke(pkg)
            if (uid != null && uid >= 0) {
                sb.append("  - AND,((UID,").append(uid).append("),(NETWORK,udp)),REJECT-DROP\n")
            } else {
                sb.append("  - AND,((PROCESS-NAME,").append(pkg).append("),(NETWORK,udp)),REJECT-DROP\n")
            }
        }

        // (B) Per-app map. In cmfa mode Mihomo can't resolve uid->package name from
        // packages.xml, so prefer UID rules (resolved from the Android
        // PackageManager) and fall back to PROCESS-NAME when the uid is unknown.
        for ((pkg, node) in appMap) {
            val uid = uidOf?.invoke(pkg)
            if (uid != null && uid >= 0) {
                sb.append("  - UID,").append(uid).append(",").append(node).append("\n")
            } else {
                sb.append("  - PROCESS-NAME,").append(pkg).append(",").append(node).append("\n")
            }
        }
        for (r in rules) sb.append(r.toClashLine()).append("\n")
        for (raw in rawRules) if (raw.isNotBlank()) sb.append("  - ").append(raw.trim()).append("\n")
        // Final-target UDP guard: if unmatched traffic goes to a proxy node that can't carry
        // UDP, block the leftover UDP too (TCP still flows through the proxy). Skipped when the
        // final target is DIRECT (per-app mode — unmapped apps legitimately use the real net).
        if (finalTarget != "DIRECT" && !targetCarriesUdp(finalTarget)) {
            sb.append("  - NETWORK,udp,REJECT-DROP\n")
        }
        // Always end with an explicit MATCH so nothing is left unrouted.
        val hasMatch = rules.any { it.isMatch } || rawRules.any { it.trim().startsWith("MATCH", true) }
        if (!hasMatch) sb.append("  - MATCH,").append(finalTarget).append("\n")

        return sb.toString()
    }

    // ---- Persistence -------------------------------------------------------

    fun toJson(): JSONObject = JSONObject().apply {
        put("nodes", JSONArray().apply { nodes.forEach { put(it.toJson()) } })
        put("appMap", JSONObject().apply { appMap.forEach { (k, v) -> put(k, v) } })
        put("bbMap", JSONObject().apply { bbMap.forEach { (k, v) -> put(k, v) } })
        put("rules", JSONArray().apply { rules.forEach { put(it.toJson()) } })
        put("rawRules", JSONArray().apply { rawRules.forEach { put(it) } })
        put("providers", JSONArray().apply { providers.forEach { put(it.toJson()) } })
        put("processMatchMode", processMatchMode.name)
        put("finalTarget", finalTarget)
        put("logLevel", logLevel)
        put("ipv6", ipv6)
        put("blockIpv6WhenOff", blockIpv6WhenOff)
        put("blockQuic", blockQuic)
        put("memConservative", memConservative)
        put("geodataMode", geodataMode)
        put("geoAutoUpdate", geoAutoUpdate)
        put("geoipUrl", geoipUrl)
        put("geositeUrl", geositeUrl)
        put("mmdbUrl", mmdbUrl)
    }

    fun save(ctx: Context) {
        SecureFileStore.writeText(ctx, FILE, toJson().toString(2))
    }

    companion object {
        private const val FILE = "routing.json"

        fun load(ctx: Context): RoutingConfig {
            if (!SecureFileStore.exists(ctx, FILE)) return RoutingConfig()
            return fromJson(JSONObject(SecureFileStore.readText(ctx, FILE)!!))
        }

        fun fromJson(o: JSONObject): RoutingConfig {
            val cfg = RoutingConfig()
            o.optJSONArray("nodes")?.let { for (i in 0 until it.length()) cfg.nodes.add(ProxyNode.fromJson(it.getJSONObject(i))) }
            o.optJSONObject("appMap")?.let { m -> m.keys().forEach { k -> cfg.appMap[k] = m.getString(k) } }
            o.optJSONObject("bbMap")?.let { m -> m.keys().forEach { k -> cfg.bbMap[k] = m.getString(k) } }
            o.optJSONArray("rules")?.let { for (i in 0 until it.length()) cfg.rules.add(Rule.fromJson(it.getJSONObject(i))) }
            o.optJSONArray("rawRules")?.let { for (i in 0 until it.length()) cfg.rawRules.add(it.getString(i)) }
            o.optJSONArray("providers")?.let { for (i in 0 until it.length()) cfg.providers.add(RuleProvider.fromJson(it.getJSONObject(i))) }
            cfg.processMatchMode = runCatching { ProcessMatchMode.valueOf(o.optString("processMatchMode", "ALWAYS")) }.getOrDefault(ProcessMatchMode.ALWAYS)
            cfg.finalTarget = o.optString("finalTarget", "DIRECT")
            cfg.logLevel = o.optString("logLevel", "warning")
            cfg.ipv6 = o.optBoolean("ipv6", false)
            cfg.blockIpv6WhenOff = o.optBoolean("blockIpv6WhenOff", true)
            cfg.blockQuic = o.optBoolean("blockQuic", true)
            cfg.memConservative = o.optBoolean("memConservative", true)
            cfg.geodataMode = o.optBoolean("geodataMode", true)
            cfg.geoAutoUpdate = o.optBoolean("geoAutoUpdate", true)
            cfg.geoipUrl = o.optString("geoipUrl", cfg.geoipUrl)
            cfg.geositeUrl = o.optString("geositeUrl", cfg.geositeUrl)
            cfg.mmdbUrl = o.optString("mmdbUrl", cfg.mmdbUrl)
            return cfg
        }
    }
}
