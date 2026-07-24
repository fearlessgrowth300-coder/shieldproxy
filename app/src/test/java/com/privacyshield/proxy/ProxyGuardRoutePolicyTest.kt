package com.privacyshield.proxy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyGuardRoutePolicyTest {
    @Test
    fun geoAndProbeFailuresNeverCloseAnUnchangedRoute() {
        val route = "route-a"

        assertFalse(
            ProxyGuardService.isConfirmedRouteIdentityViolation(
                route, route, "GEO_GUARD_FAILED"
            )
        )
        assertFalse(
            ProxyGuardService.isConfirmedRouteIdentityViolation(
                route, route, "EXIT_CHECK_FAILED"
            )
        )
        assertFalse(
            ProxyGuardService.isConfirmedRouteIdentityViolation(
                route, route, "LEAK_GUARD_FAILED"
            )
        )
    }

    @Test
    fun onlyMissingOrChangedRouteIdentityClosesTheClone() {
        assertTrue(
            ProxyGuardService.isConfirmedRouteIdentityViolation(
                "route-a", "route-b", "EXIT_VERIFIED"
            )
        )
        assertTrue(
            ProxyGuardService.isConfirmedRouteIdentityViolation(
                "route-a", "route-a", "ROUTE_MISMATCH"
            )
        )
        assertTrue(
            ProxyGuardService.isConfirmedRouteIdentityViolation(
                "route-a", "", "CONFIG_MISSING"
            )
        )
    }
}
