package com.privacyshield.proxy.core

import android.util.Base64
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Tests a proxy node WITHOUT the VPN: opens a raw tunnel (SOCKS5 or HTTP
 * CONNECT) to an IP-echo endpoint, does TLS, and reads back the exit IP, then
 * looks up its city. MUST be called off the main thread.
 */
object ProxyTester {

    data class Result(
        val ok: Boolean, val ip: String = "", val city: String = "",
        val type: String = "", val error: String = "", val reachableOnly: Boolean = false
    )

    private const val HOST = "api.ipify.org"
    private const val PORT = 443
    private const val TIMEOUT_MS = 8_000

    fun test(node: ProxyNode, lookupMetadata: Boolean = true): Result {
        if (!node.isValid()) return Result(false, error = "invalid proxy")
        // Only SOCKS5/HTTP proxies are raw TCP tunnels we can exit-IP test
        // directly. For engine-only protocols (ss/vless/hysteria2/tuic/vmess/
        // wireguard) verify the server is reachable; the real exit IP shows via
        // Check IP once the list is started (routed through the Mihomo engine).
        val t = node.type.lowercase()
        val rawTunnel = t == "socks5" || t == "socks" || t.startsWith("http")
        if (!rawTunnel) {
            return try {
                Socket().use { it.connect(InetSocketAddress(node.server, node.port), TIMEOUT_MS) }
                Result(true, reachableOnly = true)
            } catch (e: Exception) {
                Result(false, error = e.message ?: "unreachable")
            }
        }
        var socket: Socket? = null
        try {
            socket = Socket()
            socket.connect(InetSocketAddress(node.server, node.port), TIMEOUT_MS)
            socket.soTimeout = TIMEOUT_MS
            val out = socket.getOutputStream()
            val inp = socket.getInputStream()

            when {
                node.type.lowercase().startsWith("http") -> httpConnect(out, inp, node, HOST, PORT)
                else -> socks5Connect(out, inp, node, HOST, PORT) // socks5 default
            }

            val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(socket, HOST, PORT, true) as SSLSocket
            ssl.soTimeout = TIMEOUT_MS
            ssl.startHandshake()
            val sout = ssl.outputStream
            sout.write(
                ("GET /?format=text HTTP/1.1\r\nHost: $HOST\r\nUser-Agent: ShieldProxy\r\nConnection: close\r\n\r\n")
                    .toByteArray()
            )
            sout.flush()
            val body = readHttpBody(ssl.inputStream)
            val ip = body.trim()
            if (ip.isEmpty() || !ip.matches(Regex("^[0-9a-fA-F:.]+$"))) {
                return Result(false, error = "no IP returned")
            }
            val info = if (lookupMetadata) lookupInfo(node, ip) else Pair("", "")
            return Result(true, ip = ip, city = info.first, type = info.second)
        } catch (e: Exception) {
            return Result(false, error = e.message ?: e.javaClass.simpleName)
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    // ---- SOCKS5 ------------------------------------------------------------

    private fun socks5Connect(
        out: OutputStream, inp: InputStream, node: ProxyNode, targetHost: String, targetPort: Int
    ) {
        val hasAuth = node.username.isNotEmpty()
        // greeting
        if (hasAuth) out.write(byteArrayOf(0x05, 0x01, 0x02)) else out.write(byteArrayOf(0x05, 0x01, 0x00))
        out.flush()
        val sel = ByteArray(2); readFully(inp, sel)
        if (sel[0].toInt() != 0x05) throw RuntimeException("not socks5")
        when (sel[1].toInt() and 0xff) {
            0x00 -> {}
            0x02 -> {
                val u = node.username.toByteArray()
                val p = node.password.toByteArray()
                val buf = ArrayList<Byte>()
                buf.add(0x01); buf.add(u.size.toByte()); u.forEach { buf.add(it) }
                buf.add(p.size.toByte()); p.forEach { buf.add(it) }
                out.write(buf.toByteArray()); out.flush()
                val ar = ByteArray(2); readFully(inp, ar)
                if (ar[1].toInt() != 0x00) throw RuntimeException("proxy auth failed")
            }
            else -> throw RuntimeException("proxy refused auth methods")
        }
        // CONNECT to HOST:PORT by domain
        val host = targetHost.toByteArray()
        val req = ArrayList<Byte>()
        req.add(0x05); req.add(0x01); req.add(0x00); req.add(0x03)
        req.add(host.size.toByte()); host.forEach { req.add(it) }
        req.add(((targetPort shr 8) and 0xff).toByte()); req.add((targetPort and 0xff).toByte())
        out.write(req.toByteArray()); out.flush()
        val head = ByteArray(4); readFully(inp, head)
        if (head[1].toInt() != 0x00) throw RuntimeException("proxy CONNECT failed (code ${head[1].toInt()})")
        // consume bound address
        val skip = when (head[3].toInt() and 0xff) {
            0x01 -> 4 + 2
            0x04 -> 16 + 2
            0x03 -> { val l = ByteArray(1); readFully(inp, l); (l[0].toInt() and 0xff) + 2 }
            else -> 0
        }
        if (skip > 0) readFully(inp, ByteArray(skip))
    }

    // ---- HTTP CONNECT ------------------------------------------------------

    private fun httpConnect(
        out: OutputStream, inp: InputStream, node: ProxyNode, targetHost: String, targetPort: Int
    ) {
        val sb = StringBuilder()
        sb.append("CONNECT $targetHost:$targetPort HTTP/1.1\r\nHost: $targetHost:$targetPort\r\n")
        if (node.username.isNotEmpty()) {
            val cred = Base64.encodeToString("${node.username}:${node.password}".toByteArray(), Base64.NO_WRAP)
            sb.append("Proxy-Authorization: Basic $cred\r\n")
        }
        sb.append("\r\n")
        out.write(sb.toString().toByteArray()); out.flush()
        val line = readLine(inp)
        if (!line.contains(" 200")) throw RuntimeException("proxy CONNECT: $line")
        // drain remaining headers
        while (true) { val l = readLine(inp); if (l.isEmpty()) break }
    }

    // ---- helpers -----------------------------------------------------------

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var n = 0
        while (n < buf.size) {
            val r = inp.read(buf, n, buf.size - n)
            if (r < 0) throw RuntimeException("proxy closed connection")
            n += r
        }
    }

    private fun readLine(inp: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = inp.read()
            if (c < 0 || c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun readHttpBody(inp: InputStream): String {
        val reader = BufferedReader(InputStreamReader(inp))
        // skip headers
        while (true) { val l = reader.readLine() ?: break; if (l.isEmpty()) break }
        return reader.readText()
    }

    /** Best-effort city + connection-TYPE lookup through the same proxy via ip-api.com,
     *  which exposes mobile/proxy/hosting flags. For multi-accounting: Mobile = strongest,
     *  Residential = good, Datacenter/Flagged = easily detected & banned — avoid. Returns
     *  Pair(city, type). */
    private fun lookupInfo(node: ProxyNode, ip: String): Pair<String, String> {
        var socket: Socket? = null
        return try {
            val metadataHost = "ip-api.com"
            val metadataPort = 80
            socket = Socket().apply {
                connect(InetSocketAddress(node.server, node.port), TIMEOUT_MS)
                soTimeout = TIMEOUT_MS
            }
            val out = socket.getOutputStream()
            val inp = socket.getInputStream()
            if (node.type.lowercase().startsWith("http")) {
                httpConnect(out, inp, node, metadataHost, metadataPort)
            } else {
                socks5Connect(out, inp, node, metadataHost, metadataPort)
            }
            val path = "/json/$ip?fields=status,city,mobile,proxy,hosting,isp"
            out.write(
                ("GET $path HTTP/1.1\r\nHost: $metadataHost\r\n" +
                    "User-Agent: ShieldProxy\r\nConnection: close\r\n\r\n").toByteArray()
            )
            out.flush()
            val o = org.json.JSONObject(readHttpBody(inp))
            if (o.optString("status") != "success") return Pair("", "")
            val city = o.optString("city", "")
            val mobile = o.optBoolean("mobile", false)
            val proxy = o.optBoolean("proxy", false)
            val hosting = o.optBoolean("hosting", false)
            val type = when {
                hosting -> "⚠ Datacenter"
                mobile -> "📶 Mobile"
                proxy -> "⚠ Flagged"
                else -> "🏠 Residential"
            }
            Pair(city, type)
        } catch (_: Exception) {
            Pair("", "")
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }
}
