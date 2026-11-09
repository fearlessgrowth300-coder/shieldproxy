package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EngineAndLaunchGateTest {
    @Test
    fun headerFollowsTheVpnProcessMarker() {
        val marker = EngineStatus.marker("18080", 2683)
        assertEquals("18080", EngineStatus.token(marker))
        assertTrue(EngineStatus.isUp(marker, ageMs = 1_000) { it == 2683 })
        assertFalse(EngineStatus.isUp(marker, ageMs = 1_000) { false })
        assertTrue(EngineStatus.isUp(marker, ageMs = 1_000) { null })
        assertFalse(EngineStatus.isUp(marker, ageMs = EngineStatus.FRESH_MS) { null })
        assertFalse(EngineStatus.isUp("", ageMs = 0) { true })
    }

    @Test
    fun sensorOnlyGuardWarnsAndStillOpens() {
        val open = CloneLaunchGate.decide(
            ok = false,
            routeId = "route-1",
            exitIp = "203.0.113.10",
            expectedExitIp = "203.0.113.10",
            error = "Isolation guard failed: sensor",
            state = "LEAK_GUARD_FAILED"
        )
        assertNull(open.block)
        assertEquals(CloneLaunchGate.SENSOR_WARNING, open.warning)

        val dns = CloneLaunchGate.decide(
            ok = false,
            routeId = "route-1",
            exitIp = "203.0.113.10",
            expectedExitIp = "203.0.113.10",
            error = "Isolation guard failed: dns,sensor",
            state = "LEAK_GUARD_FAILED"
        )
        assertEquals("Isolation guard failed: dns,sensor", dns.block)

        val mismatch = CloneLaunchGate.decide(
            ok = false,
            routeId = "route-1",
            exitIp = "198.51.100.8",
            expectedExitIp = "203.0.113.10",
            error = "Isolation guard failed: sensor",
            state = "LEAK_GUARD_FAILED"
        )
        assertEquals("Isolation guard failed: sensor", mismatch.block)
    }

    @Test
    fun distinctExitsPassAndASharedExitFails() {
        val ok = RouteLeakCheck.assess(
            exitIp = "203.0.113.10",
            realIp = "198.51.100.8",
            listenerOpen = true,
            userConflict = false,
            containersExcluded = true,
            privateDnsDirect = true,
            ipv6Blocked = true,
            stunBlocked = true,
            killSwitchOn = true
        )
        assertTrue(ok.pass)
        assertEquals(
            setOf("203.0.113.10"),
            RouteLeakCheck.sharedExits(mapOf("a" to "203.0.113.10", "b" to "203.0.113.10"))
        )
        val real = RouteLeakCheck.assess(
            exitIp = "198.51.100.8",
            realIp = "198.51.100.8",
            listenerOpen = true,
            userConflict = false,
            containersExcluded = true,
            privateDnsDirect = true,
            ipv6Blocked = true,
            stunBlocked = true,
            killSwitchOn = true
        )
        assertFalse(real.pass)
    }
}
