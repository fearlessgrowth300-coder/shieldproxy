package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidProfileIsolationTest {
    @Test
    fun userIdComesFromTheUid() {
        assertEquals(0, AndroidProfile.userIdOf(10234))
        assertEquals(10, AndroidProfile.userIdOf(1_010_234))
    }

    @Test
    fun personalProfileKeepsLegacyNamesAndWorkProfileDoesNot() {
        assertEquals("shieldproxy", AndroidProfile.backupApp("shieldproxy", 0))
        assertEquals("_shieldbox_recovery_key_v1", AndroidProfile.backupApp("_shieldbox_recovery_key_v1", 0))
        assertEquals("shieldproxy-u10", AndroidProfile.backupApp("shieldproxy", 10))
        assertEquals("_shieldbox_recovery_key_v1-u10", AndroidProfile.backupApp("_shieldbox_recovery_key_v1", 10))
        assertEquals("alias", AndroidProfile.keyAlias("alias", 0))
        assertEquals("alias.u10", AndroidProfile.keyAlias("alias", 10))
        assertEquals("shieldproxy-exit-u0", ProfileStatus.exitApp(0))
        assertEquals("shieldproxy-exit-u10", ProfileStatus.exitApp(10))
    }

    @Test
    fun packageQueriesStayOnThisUser() {
        assertEquals(0, PackageQuery.FLAGS)
        assertTrue(PackageQuery.sameUser(1_010_234, 10))
        assertFalse(PackageQuery.sameUser(10234, 10))
    }

    @Test
    fun sameExitOrProxyAcrossAndroidUsersIsAWarning() {
        val mine = ExitOverlap.Mark(0, "198.51.100.10", ExitOverlap.proxyKey("gw.example", 1080, "alice"))
        val other = ExitOverlap.Mark(10, "198.51.100.10", ExitOverlap.proxyKey("gw.example", 1080, "alice"))
        assertEquals(1, ExitOverlap.warnings(mine, listOf(other)).size)
        val different = ExitOverlap.Mark(10, "203.0.113.5", ExitOverlap.proxyKey("other.example", 1080, "bob"))
        assertTrue(ExitOverlap.warnings(mine, listOf(different)).isEmpty())
        assertTrue(ExitOverlap.warnings(mine, listOf(mine)).isEmpty())
    }

    @Test
    fun workProfileGuidanceNamesTheWorkSettingsPage() {
        val text = AndroidProfile.vpnGuidance(true)
        assertTrue(text.contains("work profile"))
        assertTrue(text.contains("Always-on VPN"))
        assertTrue(text.contains("kill switch"))
        assertTrue(AndroidProfile.label(10, true).startsWith("Work profile"))
        assertTrue(AndroidProfile.label(0, false).startsWith("Personal profile"))
    }
}
