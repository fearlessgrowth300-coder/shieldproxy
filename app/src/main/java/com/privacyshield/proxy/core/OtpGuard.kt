package com.privacyshield.proxy.core

/** Small client-side brake; server CAPTCHA/rate limits remain the real abuse boundary. */
class OtpGuard(private val nowMs: () -> Long = System::currentTimeMillis) {
    companion object {
        const val RESEND_COOLDOWN_MS = 60_000L
        const val MAX_VERIFY_FAILURES = 5
    }

    private var nextSendAt = 0L
    private var failures = 0

    fun canSend(): Boolean = nowMs() >= nextSendAt
    fun resendSeconds(): Long = ((nextSendAt - nowMs()).coerceAtLeast(0L) + 999L) / 1000L
    fun markSent() { nextSendAt = nowMs() + RESEND_COOLDOWN_MS; failures = 0 }
    fun validCode(code: String): Boolean = code.length == 6 && code.all(Char::isDigit)
    fun recordVerifyFailure(): Int { failures++; return attemptsRemaining() }
    fun attemptsRemaining(): Int = (MAX_VERIFY_FAILURES - failures).coerceAtLeast(0)
    fun isLocked(): Boolean = failures >= MAX_VERIFY_FAILURES
}
