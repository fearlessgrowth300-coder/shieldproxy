package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthPolicyTest {
    @Test fun expiredAndNearExpiryTokensAreRejected() {
        val now = 1_000_000L
        assertFalse(SessionPolicy.tokenExpiryIsUsable(999L, now))
        assertFalse(SessionPolicy.tokenExpiryIsUsable(1_030L, now))
        assertTrue(SessionPolicy.tokenExpiryIsUsable(1_031L, now))
    }

    @Test fun serverValidationExpiresAndClockRollbackIsRejected() {
        assertTrue(SessionPolicy.validationIsFresh(1_000L, 2_000L, 2_000L))
        assertFalse(SessionPolicy.validationIsFresh(1_000L, 3_001L, 2_000L))
        assertFalse(SessionPolicy.validationIsFresh(2_000L, 1_999L, 2_000L))
    }

    @Test fun otpResendAndAttemptLimitsAreEnforced() {
        var now = 0L
        val guard = OtpGuard { now }
        assertTrue(guard.canSend())
        guard.markSent()
        assertFalse(guard.canSend())
        assertEquals(60L, guard.resendSeconds())
        repeat(4) { assertTrue(guard.recordVerifyFailure() > 0) }
        assertEquals(0, guard.recordVerifyFailure())
        assertTrue(guard.isLocked())
        now = OtpGuard.RESEND_COOLDOWN_MS
        assertTrue(guard.canSend())
    }

    @Test fun otpMustBeExactlySixDigits() {
        val guard = OtpGuard()
        assertTrue(guard.validCode("123456"))
        assertFalse(guard.validCode("12345"))
        assertFalse(guard.validCode("1234567"))
        assertFalse(guard.validCode("12a456"))
    }
}
