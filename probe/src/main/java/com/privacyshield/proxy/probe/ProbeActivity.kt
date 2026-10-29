package com.privacyshield.proxy.probe

import android.app.Activity
import android.os.Bundle
import android.util.Log
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/** Separate package so its sockets are captured by ShieldProxy's VPN. */
class ProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val host = intent.getStringExtra("host") ?: "203.0.113.10"
        val port = intent.getIntExtra("port", 9)
        Thread {
            val result = runCatching {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(host, port), 20_000)
                    // Mihomo's gVisor stack can finish the local handshake before it
                    // dials the proxy. Hold the socket so that dial is not cancelled.
                    socket.getOutputStream().write(1)
                    socket.getOutputStream().flush()
                    Thread.sleep(5_000)
                }
                "ok $host $port"
            }.getOrElse { "fail ${it.javaClass.simpleName}:${it.message}" }
            Log.i("ProbeTraffic", result)
            File(filesDir, "probe_result.txt").writeText(result)
            runOnUiThread { finish() }
        }.start()
    }
}
