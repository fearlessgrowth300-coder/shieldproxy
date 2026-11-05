package com.privacyshield.proxy

import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import java.io.File

/** Debug-only copy of the home engine control, so a tap can be proven without an account. */
class EngineMarkActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val mark = findViewById<View>(R.id.homeEngineMark)
        val row = findViewById<View>(R.id.homeEngineRow)
        val tap = View.OnClickListener {
            Log.i("ShieldVpn", "step=header-tap")
            File(filesDir, "header_tap.txt").writeText("tap class=${mark.javaClass.name}")
        }
        mark.setOnClickListener(tap)
        row.setOnClickListener(tap)
        File(filesDir, "header_ready.txt").writeText(
            "class=${mark.javaClass.name} clickable=${mark.isClickable}"
        )
    }
}
