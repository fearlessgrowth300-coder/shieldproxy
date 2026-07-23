package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdaterRolloutTest {
    @Test
    fun cohortIsStableAndVersionSpecific() {
        val id = "install-123"
        val first = Updater.rolloutBucket(id, "com.privacyshield.proxy", 18)
        assertEquals(first, Updater.rolloutBucket(id, "com.privacyshield.proxy", 18))
        assertNotEquals(first, Updater.rolloutBucket(id, "com.privacyshield.proxy", 19))
        assertTrue(first in 0..99)
    }

    @Test
    fun rolloutBoundariesAreFailSafe() {
        assertFalse(Updater.isBucketEligible("a", "com.privacyshield.proxy", 18, 0))
        assertFalse(Updater.isBucketEligible("a", "com.privacyshield.proxy", 18, -1))
        assertTrue(Updater.isBucketEligible("a", "com.privacyshield.proxy", 18, 100))
        assertTrue(Updater.isBucketEligible("a", "com.privacyshield.proxy", 18, 101))
    }

    @Test
    fun tenPercentCohortIsApproximatelyTenPercent() {
        val eligible = (0 until 10_000).count {
            Updater.isBucketEligible("install-$it", "com.privacyshield.proxy", 18, 10)
        }
        assertTrue("eligible=$eligible", eligible in 850..1150)
    }
}
