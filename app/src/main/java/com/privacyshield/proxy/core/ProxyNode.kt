package com.privacyshield.proxy.core

import org.json.JSONObject

/**
 * A single outbound proxy node (one exit IP = one account's proxy).
 * Focused on the proxy types multi-account operators actually buy
 * (SOCKS5 / HTTP residential + mobile), but the type string is passed
 * straight to Mihomo so shadowsocks/vmess/trojan also work if filled in.
 */
data class ProxyNode(
    val name: String,
    val type: String,        // socks5 | http | ss | vmess | trojan ...
    val server: String,
    val port: Int,
    val username: String = "",
    val password: String = "",
    val udp: Boolean = true,
    val tls: Boolean = false,
    // free-form extra Clash keys (cipher, uuid, sni, ...) as raw "key: value" lines
    val extraLines: List<String> = emptyList()
) {
    fun isValid(): Boolean = name.isNotBlank() && server.isNotBlank() && port in 1..65535

    /**
     * Can this node actually tunnel UDP (and therefore QUIC)?
     *  - HTTP/HTTPS proxies use CONNECT and are TCP-only — they can NEVER carry UDP.
     *  - SOCKS5 carries UDP only when UDP ASSOCIATE is enabled (`udp=true`).
     *  - The modern protocols (ss/vmess/trojan/vless/hysteria2/tuic/wireguard) carry
     *    UDP when `udp=true`.
     * When this is false, the leak-guard blocks the app's UDP/QUIC so it can't escape a
     * TCP-only proxy onto the real network.
     */
    fun carriesUdp(): Boolean = when (type.lowercase()) {
        "http", "https" -> false
        else -> udp
    }

    // ---- Sticky-session awareness (SOAX / most residential providers) --------
    // A rotating-residential username carries the session in it, e.g.
    //   package-349957-country-gb-...-sessionid-OCxAGgTQ7l1ZFhim-sessionlength-3600-bindttl-3600
    // The exit IP stays put for `sessionlength` seconds, then the provider rebinds
    // (or the session can die early). We parse these so the monitor can show a TTL
    // countdown and mint a fresh session on death instead of waiting blind.

    /** Session lifetime in seconds from `sessionlength-N`, or null if not present. */
    fun sessionLengthSec(): Int? =
        Regex("sessionlength-(\\d+)").find(username)?.groupValues?.get(1)?.toIntOrNull()

    /** The current sticky-session token from `sessionid-XXXX`, or null. */
    fun sessionId(): String? =
        Regex("sessionid-([A-Za-z0-9]+)").find(username)?.groupValues?.get(1)

    /** True if this proxy uses a rotatable sticky session we can refresh. */
    fun hasRotatableSession(): Boolean = sessionId() != null

    /** Country embedded by providers such as SOAX (`country-us`). Used only as a fallback when
     * the live exit-IP metadata service cannot return a country. */
    fun countryIsoHint(): String = Regex("(?:^|[-_])country[-_]?([A-Za-z]{2})(?:[-_]|$)")
        .find(username)?.groupValues?.get(1)?.lowercase()
        ?.let { if (it == "uk") "gb" else it }.orEmpty()

    /** Copy with the `sessionid-XXXX` token swapped for [newId] → a brand-new
     *  sticky session (new exit IP) without waiting for the dead one to expire. */
    fun withNewSession(newId: String): ProxyNode =
        copy(username = username.replaceFirst(Regex("sessionid-[A-Za-z0-9]+"), "sessionid-$newId"))

    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name); put("type", type); put("server", server); put("port", port)
        put("username", username); put("password", password)
        put("udp", udp); put("tls", tls)
        put("extraLines", org.json.JSONArray(extraLines))
    }

    /** Emits the Mihomo `proxies:` entry for this node. */
    fun toClashYaml(indent: String = "  ", serverOverride: String? = null): String {
        val sb = StringBuilder()
        sb.append(indent).append("- name: ").append(quote(name)).append("\n")
        sb.append(indent).append("  type: ").append(type).append("\n")
        sb.append(indent).append("  server: ").append(serverOverride?.takeIf { it.isNotBlank() } ?: server).append("\n")
        sb.append(indent).append("  port: ").append(port).append("\n")
        if (username.isNotBlank()) sb.append(indent).append("  username: ").append(quote(username)).append("\n")
        if (password.isNotBlank()) sb.append(indent).append("  password: ").append(quote(password)).append("\n")
        sb.append(indent).append("  udp: ").append(udp).append("\n")
        if (tls) sb.append(indent).append("  tls: true\n")
        // Protocol-specific keys (may contain nested YAML). Keep the parser's
        // relative indentation; only add the node base indent in front.
        for (line in extraLines) {
            if (line.isBlank()) continue
            for (sub in line.split("\n")) {
                if (sub.isBlank()) continue
                sb.append(indent).append("  ").append(sub.trimEnd()).append("\n")
            }
        }
        return sb.toString()
    }

    companion object {
        fun quote(s: String): String = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

        fun fromJson(o: JSONObject): ProxyNode {
            val extras = ArrayList<String>()
            o.optJSONArray("extraLines")?.let { for (i in 0 until it.length()) extras.add(it.getString(i)) }
            return ProxyNode(
                name = o.getString("name"),
                type = o.optString("type", "socks5"),
                server = o.optString("server"),
                port = o.optInt("port", 1080),
                username = o.optString("username", ""),
                password = o.optString("password", ""),
                udp = o.optBoolean("udp", true),
                tls = o.optBoolean("tls", false),
                extraLines = extras
            )
        }
    }
}
