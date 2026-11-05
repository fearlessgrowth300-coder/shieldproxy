package com.privacyshield.proxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.SystemClock
import androidx.core.content.ContextCompat
import com.privacyshield.proxy.core.CloneListeners
import com.privacyshield.proxy.core.ProxyNode
import com.privacyshield.proxy.core.RoutingConfig
import com.privacyshield.proxy.core.VaultKeyStore
import java.io.File

/**
 * Drives the engine from adb on an emulator. Release builds do not contain this activity.
 * The host runs a SOCKS5 server; the emulator reaches it at 10.0.2.2.
 */
class EmulatorSmokeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val cmd = intent.getStringExtra("cmd") ?: "start"
        val port = intent.getIntExtra("proxyPort", 18080)
        val result = runCatching { execute(cmd, port) }.getOrElse { "error=${it.javaClass.simpleName}:${it.message}" }
        File(filesDir, "smoke_result.txt").writeText(result)
        finish()
    }

    private fun execute(cmd: String, port: Int): String {
        if (!VaultKeyStore.isReady(this)) {
            VaultKeyStore.provision(this, "emulator@localhost", ByteArray(32) { (it + 3).toByte() })
        }
        return when (cmd) {
            "stop" -> {
                startService(Intent(this, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_STOP))
                "stopped"
            }
            "status" -> if (ShieldVpnService.isRunning(this)) "header=on" else "header=off"
            "open-clone" -> openClone()
            "scan" -> {
                startActivity(Intent(this, LeakTestActivity::class.java)
                    .putExtra("autoRun", true)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                "scan-started"
            }
            else -> {
                val began = SystemClock.elapsedRealtime()
                writeRoute(port)
                if (VpnService.prepare(this) != null) return "prepare=needed"
                ContextCompat.startForegroundService(
                    this,
                    Intent(this, ShieldVpnService::class.java).setAction(ShieldVpnService.ACTION_START)
                )
                "started port=$port dispatchMs=${SystemClock.elapsedRealtime() - began}"
            }
        }
    }

    private fun writeRoute(port: Int) {
        val cfg = RoutingConfig().apply {
            nodes.add(ProxyNode(name = "emu", type = "socks5", server = "10.0.2.2", port = port, udp = true))
            appMap["com.privacyshield.proxy.probe"] = "emu"
            bbMap[CloneListeners.tag("emu.bridge", 1, "com.android.chrome")] = "emu"
            finalTarget = "emu"
            geoAutoUpdate = false
            geodataMode = false
            ipv6 = false
        }
        cfg.save(this)
        val listener = CloneListeners.portFor("emu.bridge", 1, "com.android.chrome")
        File(filesDir, "clone_listener_port.txt").writeText(listener.toString())
        val tag = CloneListeners.tag("emu.bridge", 1, "com.android.chrome")
        File(filesDir, "clone_listener_auth.txt").writeText(
            CloneListeners.socksUser(tag) + " " + CloneListeners.socksPassword(tag)
        )
    }

    /** What Open apps does for one clone: listener handshake, then the launch gate. */
    private fun openClone(): String {
        val port = CloneListeners.portFor("emu.bridge", 1, "com.android.chrome")
        val tag = CloneListeners.tag("emu.bridge", 1, "com.android.chrome")
        val socks = runCatching {
            cloneSocks(port, CloneListeners.socksUser(tag), CloneListeners.socksPassword(tag))
            "socks=ok"
        }.getOrElse { "socks=fail:${it.javaClass.simpleName}:${it.message}" }
        val gate = com.privacyshield.proxy.core.CloneLaunchGate.decide(
            ok = false,
            routeId = "emu-route",
            exitIp = "203.0.113.10",
            expectedExitIp = "203.0.113.10",
            error = "Isolation guard failed: sensor",
            state = "LEAK_GUARD_FAILED"
        )
        val dns = com.privacyshield.proxy.core.CloneLaunchGate.decide(
            ok = false,
            routeId = "emu-route",
            exitIp = "203.0.113.10",
            expectedExitIp = "203.0.113.10",
            error = "Isolation guard failed: dns",
            state = "LEAK_GUARD_FAILED"
        )
        val header = if (ShieldVpnService.isRunning(this)) "header=on" else "header=off"
        val open = if (gate.block == null) "open=allowed" else "open=blocked"
        return "$open warning=sensor $header $socks dnsBlocked=${dns.block != null}"
    }

    private fun cloneSocks(port: Int, user: String, pass: String) {
        java.net.Socket().use { socket ->
            socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 5000)
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            output.write(byteArrayOf(0x05, 0x01, 0x02))
            output.flush()
            val method = ByteArray(2)
            readFully(input, method)
            if (method[0] != 0x05.toByte() || method[1] != 0x02.toByte()) {
                error("socks method ${method[1]}")
            }
            val userBytes = user.toByteArray(Charsets.UTF_8)
            val passBytes = pass.toByteArray(Charsets.UTF_8)
            output.write(byteArrayOf(0x01, userBytes.size.toByte()) + userBytes +
                byteArrayOf(passBytes.size.toByte()) + passBytes)
            output.flush()
            val auth = ByteArray(2)
            readFully(input, auth)
            if (auth[1] != 0.toByte()) error("socks auth ${auth[1]}")
            output.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 203.toByte(), 0, 113, 10, 0, 9))
            output.flush()
            val reply = ByteArray(10)
            readFully(input, reply)
            if (reply[1] != 0.toByte()) error("socks connect ${reply[1]}")
        }
    }

    private fun readFully(input: java.io.InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) error("socks closed")
            off += n
        }
    }
}
