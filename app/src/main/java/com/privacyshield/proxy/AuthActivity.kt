package com.privacyshield.proxy

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.CountDownTimer
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.privacyshield.proxy.core.Supabase
import com.privacyshield.proxy.core.VaultKeyStore
import com.privacyshield.proxy.core.OtpGuard
import com.privacyshield.proxy.core.SecureFileStore
import com.privacyshield.proxy.core.SupaSync

/**
 * Passwordless sign-in gate: enter your email → get a 6-digit code → enter it → you're in.
 * The same flow creates the account on first use (no password to set, remember, or reset).
 * Shown before MainActivity whenever no session is stored.
 */
class AuthActivity : AppCompatActivity() {

    private var codeSent = false
    private lateinit var subtitle: TextView
    private lateinit var emailF: EditText
    private lateinit var codeF: EditText
    private lateinit var primary: Button
    private lateinit var resend: TextView
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private val otpGuard = OtpGuard()
    private var sentEmail: String? = null
    private var resendTimer: CountDownTimer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pad = (resources.displayMetrics.density * 24).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(pad, pad, pad, pad)
            setBackgroundColor(Color.parseColor("#121016"))
        }
        root.addView(TextView(this).apply {
            text = "🛡 ShieldProxy"; textSize = 26f; setTextColor(Color.WHITE)
            setTypeface(typeface, Typeface.BOLD); gravity = Gravity.CENTER
        })
        subtitle = TextView(this).apply {
            text = "Log in or sign up with your email"; textSize = 16f
            setTextColor(Color.parseColor("#B9A6E0")); gravity = Gravity.CENTER
            setPadding(0, 8, 0, pad)
        }
        root.addView(subtitle)
        emailF = EditText(this).apply {
            hint = "Email"; setHintTextColor(Color.parseColor("#7A7290")); setTextColor(Color.WHITE)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        }
        root.addView(emailF)
        codeF = EditText(this).apply {
            hint = "6-digit code"; setHintTextColor(Color.parseColor("#7A7290")); setTextColor(Color.WHITE)
            inputType = InputType.TYPE_CLASS_NUMBER; visibility = View.GONE
        }
        root.addView(codeF)
        primary = Button(this).apply {
            text = "Send code"; isAllCaps = false
            setOnClickListener { onPrimary() }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = pad }
        }
        root.addView(primary)
        progress = ProgressBar(this).apply {
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { gravity = Gravity.CENTER; topMargin = pad }
        }
        root.addView(progress)
        status = TextView(this).apply {
            setTextColor(Color.parseColor("#FF6B6B")); gravity = Gravity.CENTER; setPadding(0, 16, 0, 0)
        }
        root.addView(status)
        resend = TextView(this).apply {
            text = "Resend code"; setTextColor(Color.parseColor("#B9A6E0"))
            gravity = Gravity.CENTER; setPadding(0, pad, 0, 0); visibility = View.GONE
            setOnClickListener { sendCode() }
        }
        root.addView(resend)

        setContentView(ScrollView(this).apply { addView(root) })
        migrateExistingSession()
    }

    private fun migrateExistingSession() {
        if (!Supabase.hasStoredSession(this)) return
        // Already unlocked on this device → straight in, no network needed (works offline).
        // The session never expires; only an explicit Log out ends it.
        // Stored session but the local key isn't set up yet (fresh install / new phone): fetch the
        // account key and restore data. NEVER log out on failure — just let the user retry.
        setBusy(true)
        status.setTextColor(Color.parseColor("#B9A6E0"))
        status.text = "Checking your account..."
        Thread {
            val valid = Supabase.validateStoredSession(this)
            if (!valid) {
                runOnUiThread {
                    setBusy(false)
                    status.setTextColor(Color.parseColor("#FFB74D"))
                    if (Supabase.hasStoredSession(this)) {
                        status.text = "Couldn't verify your account. Check your connection, then retry."
                        primary.text = "Retry"
                        primary.setOnClickListener { migrateExistingSession() }
                    } else {
                        status.text = "Your session expired. Enter your email to get a new 6-digit code."
                        primary.text = "Send code"
                        primary.setOnClickListener { onPrimary() }
                    }
                }
                return@Thread
            }
            try {
                val email = Supabase.email(this) ?: error("Account email is missing")
                provisionAccountKey(email)
                runCatching { SupaSync.pull(this) }   // restore proxies + lists
                runOnUiThread { openMain() }
            } catch (_: Exception) {
                runOnUiThread {
                    setBusy(false)
                    status.setTextColor(Color.parseColor("#FFB74D"))
                    status.text = "Couldn't reach the server. Check your connection, then tap Continue."
                    primary.text = "Continue"
                    primary.setOnClickListener { migrateExistingSession() }
                }
            }
        }.start()
    }

    private fun onPrimary() = if (!codeSent) sendCode() else verifyCode()

    /** Step 1: send (or resend) the 6-digit code. Email field stays editable so a typo is fixable. */
    private fun sendCode() {
        val email = emailF.text.toString().trim()
        if (email.isEmpty() || !email.contains("@")) { showError("Enter a valid email."); return }
        if (!otpGuard.canSend()) {
            showError("Please wait ${otpGuard.resendSeconds()} seconds before requesting another code.")
            return
        }
        setBusy(true)
        Thread {
            try {
                Supabase.requestEmailCode(this, email)
                runOnUiThread {
                    setBusy(false)
                    otpGuard.markSent()
                    codeSent = true
                    sentEmail = email
                    emailF.isEnabled = false
                    codeF.visibility = View.VISIBLE
                    codeF.requestFocus()
                    primary.text = "Verify & continue"
                    resend.visibility = View.VISIBLE
                    startResendCooldown()
                    status.setTextColor(Color.parseColor("#69F0AE"))
                    status.text = "We emailed a 6-digit code to $email. Enter it above."
                }
            } catch (e: Exception) {
                runOnUiThread { setBusy(false); showError(e.message ?: "Could not send the code.") }
            }
        }.start()
    }

    /** Step 2: verify the code → session → provision the recovery key → into the app. */
    private fun verifyCode() {
        val email = sentEmail ?: emailF.text.toString().trim()
        val code = codeF.text.toString().trim()
        if (!otpGuard.validCode(code)) { showError("Enter exactly 6 digits."); return }
        if (otpGuard.isLocked()) { showError("Too many failed attempts. Request a new code."); return }
        setBusy(true)
        Thread {
            try {
                Supabase.verifyEmailCode(this, email, code)
                // The account-held recovery key survives future logins; it's wrapped by this device's Keystore.
                provisionAccountKey(email)
                // Restore this account's proxies + lists from Supabase (survives new phones / key changes).
                runCatching { SupaSync.pull(this) }
                runOnUiThread { openMain() }
            } catch (e: Exception) {
                runOnUiThread {
                    setBusy(false)
                    val left = otpGuard.recordVerifyFailure()
                    if (left == 0) {
                        codeSent = false
                        sentEmail = null
                        emailF.isEnabled = true
                        codeF.visibility = View.GONE
                        primary.text = "Send new code"
                        showError("Too many failed attempts. Wait for the resend timer, then request a new code.")
                    } else showError("${e.message ?: "Could not verify the code."} $left attempt(s) left.")
                }
            }
        }.start()
    }

    private fun showError(m: String) {
        status.setTextColor(Color.parseColor("#FF6B6B")); status.text = m
    }

    private fun provisionAccountKey(email: String) {
        val candidates = Supabase.getBackupKeyCandidates(this)
        val recovered = SecureFileStore.recoverCompatibleAccountKey(this, email, candidates)
        if (!recovered && SecureFileStore.hasProtectedFiles(this)) {
            error("None of the account recovery keys matched the protected proxy data")
        }
        if (!recovered && (!VaultKeyStore.isReady(this) || !VaultKeyStore.belongsTo(this, email))) {
            VaultKeyStore.provision(this, email, candidates.first())
        }
    }

    private fun setBusy(busy: Boolean) {
        progress.visibility = if (busy) View.VISIBLE else View.GONE
        primary.isEnabled = !busy
        resend.isEnabled = !busy && otpGuard.canSend()
    }

    private fun startResendCooldown() {
        resendTimer?.cancel()
        resendTimer = object : CountDownTimer(OtpGuard.RESEND_COOLDOWN_MS, 1_000L) {
            override fun onTick(ms: Long) {
                resend.isEnabled = false
                resend.text = "Resend code in ${(ms + 999L) / 1_000L}s"
            }
            override fun onFinish() { resend.text = "Resend code"; resend.isEnabled = true }
        }.start()
    }

    override fun onDestroy() {
        resendTimer?.cancel()
        super.onDestroy()
    }

    private fun openMain() {
        setResult(Activity.RESULT_OK)
        startActivity(Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
        finish()
    }
}
