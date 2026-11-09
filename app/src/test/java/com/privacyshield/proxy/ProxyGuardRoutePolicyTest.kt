package com.privacyshield.proxy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyGuardRoutePolicyTest {
    @Test
    fun killSwitchStopsGeoLeakAndExitFailures() {
        assertTrue(stopped(state = "GEO_GUARD_FAILED"))
        assertTrue(stopped(state = "EXIT_CHECK_FAILED"))
        assertTrue(stopped(state = "LEAK_GUARD_FAILED"))
        assertTrue(stopped(routeOk = false, state = "EXIT_CHECK_FAILED"))
        assertTrue(stopped(observedExit = "203.0.113.8"))
        assertTrue(ProxyGuardService.proxyFailureShouldStop(true, strikes = 3, limit = 3))
    }

    @Test
    fun killSwitchKeepsAMatchingVerifiedRoute() {
        assertFalse(stopped())
        assertFalse(ProxyGuardService.proxyFailureShouldStop(true, strikes = 2, limit = 3))
    }

    @Test
    fun optOutKeepsGeoAndProbeFailuresOpen() {
        assertFalse(stopped(killSwitch = false, state = "GEO_GUARD_FAILED"))
        assertFalse(stopped(killSwitch = false, state = "EXIT_CHECK_FAILED"))
        assertFalse(stopped(killSwitch = false, state = "LEAK_GUARD_FAILED"))
        assertFalse(stopped(killSwitch = false, routeOk = false))
        assertFalse(stopped(killSwitch = false, observedExit = "203.0.113.8"))
    }

    @Test
    fun optOutStillStopsAChangedRouteIdentity() {
        assertTrue(
            ProxyGuardService.shouldStopClone(
                killSwitchEnabled = false,
                expectedRouteId = "route-a",
                observedRouteId = "route-b",
                state = "EXIT_VERIFIED",
                expectedExitIp = "198.51.100.10",
                observedExitIp = "198.51.100.10",
                routeOk = true
            )
        )
        assertTrue(
            ProxyGuardService.shouldStopClone(
                killSwitchEnabled = false,
                expectedRouteId = "route-a",
                observedRouteId = "route-a",
                state = "ROUTE_MISMATCH",
                expectedExitIp = "198.51.100.10",
                observedExitIp = "198.51.100.10",
                routeOk = true
            )
        )
        assertTrue(
            ProxyGuardService.shouldStopClone(
                killSwitchEnabled = false,
                expectedRouteId = "route-a",
                observedRouteId = "",
                state = "CONFIG_MISSING",
                expectedExitIp = "198.51.100.10",
                observedExitIp = "",
                routeOk = false
            )
        )
    }

    private fun stopped(
        killSwitch: Boolean = true,
        state: String = "EXIT_VERIFIED",
        routeOk: Boolean = true,
        observedExit: String = "198.51.100.10"
    ): Boolean = ProxyGuardService.shouldStopClone(
        killSwitchEnabled = killSwitch,
        expectedRouteId = "route-a",
        observedRouteId = "route-a",
        state = state,
        expectedExitIp = "198.51.100.10",
        observedExitIp = observedExit,
        routeOk = routeOk
    )
}
