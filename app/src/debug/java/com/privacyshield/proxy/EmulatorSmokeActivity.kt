package com.privacyshield.proxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.SystemClock
import androidx.core.content.ContextCompat
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
            finalTarget = "emu"
            geoAutoUpdate = false
            geodataMode = false
            ipv6 = false
        }
        cfg.save(this)
    }
}
