package com.privacyshield.proxy.core

import android.net.Uri
import android.util.Base64
import org.json.JSONObject
import java.net.URLDecoder

/**
 * Parses proxy share-links / configs into a Mihomo (Clash.Meta) proxy node.
 * Supports the modern protocols used by high-quality 4G/5G proxies:
 *   ss:// (Shadowsocks), vless:// (incl. Reality), trojan://,
 *   hysteria2:// / hy2://, tuic://, vmess://, and WireGuard .conf text.
 *
 * Protocol-specific keys go into ProxyNode.extraLines as ready Mihomo YAML
 * (relative indentation preserved), so the config generator just emits them.
 */
object ShareLink {

    fun parse(raw: String): ProxyNode? {
        val s = raw.trim()
        return try {
            when {
                s.startsWith("ss://") -> ss(s)
                s.startsWith("vless://") -> vless(s)
                s.startsWith("trojan://") -> trojan(s)
                s.startsWith("hysteria2://") || s.startsWith("hy2://") -> hysteria2(s)
                s.startsWith("tuic://") -> tuic(s)
                s.startsWith("vmess://") -> vmess(s)
                s.contains("[Interface]") && s.contains("[Peer]") -> wireguard(s)
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun dec(s: String): String = try { URLDecoder.decode(s, "UTF-8") } catch (_: Exception) { s }
    private fun b64(s: String): String = String(Base64.decode(s.replace('-', '+').replace('_', '/'), Base64.DEFAULT))
    private fun frag(s: String): String = if (s.contains("#")) dec(s.substringAfterLast("#")) else ""
    private fun q(uri: Uri, k: String): String? = uri.getQueryParameter(k)

    // ss://base64(method:pass)@host:port#name  OR  ss://base64(method:pass@host:port)#name
    private fun ss(s: String): ProxyNode {
        val body = s.removePrefix("ss://").substringBefore("#")
        val name = frag(s).ifBlank { "ss" }
        val method: String; val pass: String; val host: String; val port: Int
        if (body.contains("@")) {
            val userInfo = body.substringBefore("@")
            val decoded = if (userInfo.contains(":")) userInfo else b64(userInfo)
            method = decoded.substringBefore(":")
            pass = decoded.substringAfter(":")
            val hp = body.substringAfter("@").substringBefore("?")
            host = hp.substringBeforeLast(":"); port = hp.substringAfterLast(":").toInt()
        } else {
            val decoded = b64(body)
            method = decoded.substringBefore(":")
            val rest = decoded.substringAfter(":")
            pass = rest.substringBeforeLast("@")
            val hp = rest.substringAfterLast("@")
            host = hp.substringBeforeLast(":"); port = hp.substringAfterLast(":").toInt()
        }
        return ProxyNode(
            name = name, type = "ss", server = host, port = port, password = pass, udp = true,
            extraLines = listOf("cipher: $method")
        )
    }

    private fun vless(s: String): ProxyNode {
        val u = Uri.parse(s)
        val uuid = u.userInfo ?: ""
        val host = u.host ?: ""; val port = u.port
        val name = frag(s).ifBlank { host }
        val extra = arrayListOf("uuid: $uuid", "network: ${q(u, "type") ?: "tcp"}")
        q(u, "flow")?.let { if (it.isNotBlank()) extra.add("flow: $it") }
        val security = q(u, "security") ?: ""
        val sni = q(u, "sni") ?: q(u, "peer") ?: ""
        val tls = security == "tls" || security == "reality"
        if (sni.isNotBlank()) extra.add("servername: $sni")
        q(u, "fp")?.let { extra.add("client-fingerprint: $it") }
        if (security == "reality") {
            extra.add("reality-opts:")
            q(u, "pbk")?.let { extra.add("  public-key: $it") }
            q(u, "sid")?.let { extra.add("  short-id: \"$it\"") }
        }
        q(u, "serviceName")?.let { if ((q(u, "type") == "grpc")) extra.add("grpc-opts:\n  grpc-service-name: $it") }
        return ProxyNode(name = name, type = "vless", server = host, port = port, udp = true, tls = tls, extraLines = extra)
    }

    private fun trojan(s: String): ProxyNode {
        val u = Uri.parse(s)
        val pass = u.userInfo ?: ""
        val host = u.host ?: ""; val port = u.port
        val name = frag(s).ifBlank { host }
        val extra = arrayListOf<String>()
        (q(u, "sni") ?: q(u, "peer"))?.let { if (it.isNotBlank()) extra.add("sni: $it") }
        q(u, "fp")?.let { extra.add("client-fingerprint: $it") }
        return ProxyNode(name = name, type = "trojan", server = host, port = port, password = pass, udp = true, extraLines = extra)
    }

    private fun hysteria2(s: String): ProxyNode {
        val norm = s.replace("hy2://", "hysteria2://")
        val u = Uri.parse(norm)
        val pass = u.userInfo ?: ""
        val host = u.host ?: ""; val port = if (u.port > 0) u.port else 443
        val name = frag(s).ifBlank { host }
        val extra = arrayListOf<String>()
        q(u, "sni")?.let { if (it.isNotBlank()) extra.add("sni: $it") }
        q(u, "obfs")?.let { extra.add("obfs: $it") }
        q(u, "obfs-password")?.let { extra.add("obfs-password: $it") }
        if (q(u, "insecure") == "1") extra.add("skip-cert-verify: true")
        return ProxyNode(name = name, type = "hysteria2", server = host, port = port, password = pass, udp = true, extraLines = extra)
    }

    // tuic://uuid:password@host:port?params#name
    private fun tuic(s: String): ProxyNode {
        val u = Uri.parse(s)
        val info = u.userInfo ?: ""
        val uuid = info.substringBefore(":")
        val pass = info.substringAfter(":", "")
        val host = u.host ?: ""; val port = u.port
        val name = frag(s).ifBlank { host }
        val extra = arrayListOf("uuid: $uuid")
        q(u, "sni")?.let { if (it.isNotBlank()) extra.add("sni: $it") }
        extra.add("congestion-controller: ${q(u, "congestion_control") ?: "bbr"}")
        extra.add("udp-relay-mode: ${q(u, "udp_relay_mode") ?: "native"}")
        q(u, "alpn")?.let { extra.add("alpn:\n  - ${it.substringBefore(',')}") }
        if (q(u, "allow_insecure") == "1") extra.add("skip-cert-verify: true")
        return ProxyNode(name = name, type = "tuic", server = host, port = port, password = pass, udp = true, extraLines = extra)
    }

    private fun vmess(s: String): ProxyNode {
        val json = JSONObject(b64(s.removePrefix("vmess://")))
        val host = json.optString("add"); val port = json.optString("port").toIntOrNull() ?: 443
        val name = json.optString("ps", host)
        val extra = arrayListOf(
            "uuid: ${json.optString("id")}",
            "alterId: ${json.optString("aid", "0")}",
            "cipher: ${json.optString("scy", "auto")}",
            "network: ${json.optString("net", "tcp")}"
        )
        if (json.optString("tls") == "tls") { /* tls flag below */ }
        json.optString("sni").takeIf { it.isNotBlank() }?.let { extra.add("servername: $it") }
        json.optString("host").takeIf { it.isNotBlank() && json.optString("net") == "ws" }?.let {
            extra.add("ws-opts:\n  path: ${json.optString("path", "/")}\n  headers:\n    Host: $it")
        }
        return ProxyNode(name = name, type = "vmess", server = host, port = port,
            udp = true, tls = json.optString("tls") == "tls", extraLines = extra)
    }

    // WireGuard wg-quick .conf
    private fun wireguard(s: String): ProxyNode {
        fun field(section: String, key: String): String? {
            val body = s.substringAfter("[$section]").substringBefore("[", "")
            return body.lineSequence().map { it.trim() }
                .firstOrNull { it.startsWith("$key", true) && it.contains("=") }
                ?.substringAfter("=")?.trim()
        }
        val priv = field("Interface", "PrivateKey") ?: ""
        val address = field("Interface", "Address") ?: ""
        val ip4 = address.split(",").firstOrNull { it.contains(".") }?.substringBefore("/")?.trim() ?: ""
        val pub = field("Peer", "PublicKey") ?: ""
        val psk = field("Peer", "PresharedKey")
        val endpoint = field("Peer", "Endpoint") ?: ""
        val host = endpoint.substringBeforeLast(":"); val port = endpoint.substringAfterLast(":").toIntOrNull() ?: 51820
        val extra = arrayListOf("private-key: $priv", "public-key: $pub", "ip: $ip4")
        if (!psk.isNullOrBlank()) extra.add("pre-shared-key: $psk")
        extra.add("udp: true")
        return ProxyNode(name = "wireguard", type = "wireguard", server = host, port = port, udp = true, extraLines = extra)
    }
}
