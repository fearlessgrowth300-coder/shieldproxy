package com.privacyshield.proxy.core

object SessionPolicy {
    fun tokenExpiryIsUsable(expiresEpochSeconds: Long, nowMs: Long, skewSeconds: Long = 30L): Boolean =
        expiresEpochSeconds > (nowMs / 1_000L) + skewSeconds

    fun validationIsFresh(validatedAtMs: Long, nowMs: Long, maxAgeMs: Long): Boolean =
        validatedAtMs > 0L && nowMs >= validatedAtMs && nowMs - validatedAtMs <= maxAgeMs
}
