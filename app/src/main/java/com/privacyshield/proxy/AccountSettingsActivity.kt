package com.privacyshield.proxy

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.privacyshield.proxy.core.BlackBoxBridge
import com.privacyshield.proxy.core.CloudSync
import com.privacyshield.proxy.core.DriveFolderStore
import com.privacyshield.proxy.core.RemoteControl
import com.privacyshield.proxy.core.Supabase
import com.privacyshield.proxy.core.VaultKeyStore

/** A real, persistent settings page. Backup/restore actions return to MainActivity for execution. */
class AccountSettingsActivity : AppCompatActivity() {
    private lateinit var connectionStatus: TextView
    private lateinit var connectionButton: Button
    private lateinit var killStatus: TextView
    private lateinit var killButton: Button

    companion object {
        const val EXTRA_ACTION = "account_action"
        const val ACTION_BACKUP = "backup"
        const val ACTION_RESTORE = "restore"
        const val ACTION_DRIVE = "drive"
        const val ACTION_LOGOUT = "logout"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Supabase.isSignedIn(this) || !VaultKeyStore.isReady(this)) {
            startActivity(Intent(this, AuthActivity::class.java))
            finish(); return
        }

        val pad = (20 * resources.displayMetrics.density).toInt()
        val gap = (10 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            setBackgroundColor(Color.parseColor("#121016"))
        }
        root.addView(TextView(this).apply {
            text = "Settings / Account & Backup"
            textSize = 25f; setTextColor(Color.WHITE)
            setTypeface(typeface, android.graphics.Typeface.BOLD)
        })
        root.addView(TextView(this).apply {
            text = "Signed-in email\n${Supabase.email(this@AccountSettingsActivity) ?: "Unknown"}\n\n" +
                "Account type\nPasswordless email code\n\nGoogle Drive\n" +
                if (DriveFolderStore.isConnected(this@AccountSettingsActivity)) "Connected" else "Not connected"
            textSize = 16f; setTextColor(Color.LTGRAY); setPadding(0, gap, 0, gap)
        })
        root.addView(TextView(this).apply {
            text = "BlackBox connection"
            textSize = 19f; setTextColor(Color.WHITE); setPadding(0, gap, 0, 0)
        })
        connectionStatus = TextView(this).apply {
            text = "Checking signed connection..."
            textSize = 15f; setTextColor(Color.LTGRAY); setPadding(0, gap, 0, 0)
        }
        root.addView(connectionStatus)
        connectionButton = actionButton("Connect / verify BlackBox") { verifyBlackBoxConnection() }
        root.addView(connectionButton)
        root.addView(actionButton("Select / change Google Drive folder") { emit(ACTION_DRIVE) })
        root.addView(actionButton("Back up proxies and routes to Drive") { emit(ACTION_BACKUP) })
        root.addView(actionButton("Restore proxies and routes from Drive") { emit(ACTION_RESTORE) })

        root.addView(sectionLabel("Security checks"))
        root.addView(actionButton("Leak test (DNS / IPv6 / proxy)") {
            startActivity(Intent(this, LeakTestActivity::class.java))
        })

        root.addView(sectionLabel("Emergency kill switch"))
        killStatus = TextView(this).apply { textSize = 14f; setPadding(0, gap, 0, 0) }
        root.addView(killStatus)
        killButton = actionButton("…") { toggleKill() }
        root.addView(killButton)
        renderKill()

        root.addView(TextView(this).apply {
            text = "Sign-in\nPasswordless — a 6-digit code is emailed to you each time you log in. " +
                "Nothing to remember or reset."
            textSize = 15f; setTextColor(Color.LTGRAY); setPadding(0, pad, 0, gap)
        })
        root.addView(actionButton("Log out") { emit(ACTION_LOGOUT) }.apply { setPadding(0, gap, 0, gap) })
        root.addView(actionButton("Back") { finish() })
        setContentView(ScrollView(this).apply { addView(root) })
        verifyBlackBoxConnection()
    }

    private fun verifyBlackBoxConnection() {
        connectionButton.isEnabled = false
        connectionStatus.setTextColor(Color.LTGRAY)
        connectionStatus.text = "Checking signed connection..."
        Thread {
            val result = BlackBoxBridge.connectionStatus(this)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                connectionButton.isEnabled = true
                if (result.reachable && result.ready && result.sameAccount) {
                    connectionStatus.setTextColor(Color.parseColor("#69F0AE"))
                    val version = result.versionName.takeIf { it.isNotBlank() }?.let { " v$it" }.orEmpty()
                    connectionStatus.text = "Connected successfully to BlackBox$version\n" +
                        "Trusted signature • Same account • Ready"
                } else {
                    connectionStatus.setTextColor(Color.parseColor("#FF8A80"))
                    connectionStatus.text = "Not connected\n${result.error}"
                }
            }
        }.start()
    }

    private fun sectionLabel(text: String) = TextView(this).apply {
        this.text = text; textSize = 19f; setTextColor(Color.WHITE)
        setPadding(0, (16 * resources.displayMetrics.density).toInt(), 0, 0)
    }

    // ---- Emergency kill switch ----
    private fun renderKill() {
        val on = RemoteControl.isKilled(this)
        killStatus.setTextColor(if (on) Color.parseColor("#FF8A80") else Color.parseColor("#69F0AE"))
        killStatus.text = if (on)
            "ARMED — all clones force-closed and launches blocked.\n${RemoteControl.killedReason(this)}".trim()
        else "Off — clones can open normally."
        killButton.text = if (on) "Disarm kill switch" else "ARM kill switch (close all clones now)"
    }

    private fun toggleKill() {
        val turnOn = !RemoteControl.isKilled(this)
        killButton.isEnabled = false
        Thread {
            val ok = runCatching {
                RemoteControl.setKill(this, turnOn, if (turnOn) "Armed from settings" else "")
            }.isSuccess
            runOnUiThread {
                killButton.isEnabled = true
                if (!ok) toast("Couldn't reach the server — try again when online.")
                renderKill()
            }
        }.start()
    }

    private fun testRecoveryKey() {
        toast("Testing recovery key…")
        Thread {
            val ok = runCatching { CloudSync.recoveryKeySelfTest(this) }.getOrDefault(false)
            runOnUiThread {
                AlertDialog.Builder(this)
                    .setTitle("Recovery key")
                    .setMessage(
                        if (ok) "✓ Your recovery key works — existing backups are decryptable on a new phone."
                        else "⚠ Could not verify the recovery key. Backups may not be restorable — connect Drive and back up again."
                    )
                    .setPositiveButton("OK", null).show()
            }
        }.start()
    }

    private fun showBackupHistory() {
        toast("Loading backup history…")
        Thread {
            val snaps = runCatching { CloudSync.history(this) }.getOrDefault(emptyList())
            runOnUiThread {
                if (snaps.isEmpty()) { toast("No backups found yet."); return@runOnUiThread }
                val fmt = java.text.SimpleDateFormat("MMM d, HH:mm", java.util.Locale.getDefault())
                val labels = snaps.map { "${fmt.format(java.util.Date(it.createdAt))} · ${it.plainBytes / 1024} KB" }
                    .toTypedArray()
                AlertDialog.Builder(this)
                    .setTitle("Restore a point in time")
                    .setItems(labels) { _, which ->
                        AlertDialog.Builder(this)
                            .setTitle("Restore this backup?")
                            .setMessage("Replaces your current proxies & lists with:\n${labels[which]}")
                            .setPositiveButton("Restore") { _, _ ->
                                BackupService.startRestoreFrom(this, snaps[which].name)
                                toast("Restoring… watch the notification.")
                            }
                            .setNegativeButton("Cancel", null).show()
                    }
                    .setNegativeButton("Close", null).show()
            }
        }.start()
    }

    private fun toast(m: String) = android.widget.Toast.makeText(this, m, android.widget.Toast.LENGTH_SHORT).show()

    private fun actionButton(label: String, action: (View) -> Unit) = Button(this).apply {
        text = label; isAllCaps = false; textSize = 15f
        setOnClickListener(action)
        val gap = (6 * resources.displayMetrics.density).toInt()
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { topMargin = gap }
        gravity = Gravity.CENTER
    }

    private fun emit(action: String) {
        setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_ACTION, action))
        finish()
    }
}
