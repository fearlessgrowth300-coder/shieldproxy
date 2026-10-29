package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteIsolationConfigTest {
    private val authority = "top.niunaijun.blackbox.bridge"

    @Test
    fun bbMapBecomesAPinnedSocksListenerAndARejectRule() {
        val cfg = RoutingConfig()
        cfg.nodes.add(node("London", tls = true))
        cfg.bbMap[tag(3, "com.instagram.android")] = "London"
        val yaml = cfg.toClashYaml(uidOf = { pkg ->
            if (pkg == "top.niunaijun.blackbox") 1042 else null
        })
        val port = CloneListeners.portFor(authority, 3, "com.instagram.android")
        assertTrue(yaml.contains("listeners:"))
        assertTrue(yaml.contains("type: socks"))
        assertTrue(yaml.contains("listen: 127.0.0.1"))
        assertTrue(yaml.contains("port: $port"))
        assertTrue(yaml.contains("proxy: \"London\""))
        assertTrue(yaml.contains("IN-NAME,bbp$port,London"))
        assertTrue(yaml.contains("UID,1042,REJECT-DROP"))
        assertTrue(yaml.contains("tls: true"))
    }

    @Test
    fun listenerPortsStayPutWhenAnotherCloneIsAdded() {
        val first = tag(1, "com.instagram.android")
        val before = CloneListeners.assignPorts(listOf(first))
        val after = CloneListeners.assignPorts(listOf(tag(2, "com.whatsapp"), first))
        assertEquals(before.getValue(first), after.getValue(first))
    }

    @Test
    fun tlsAndGeoTravelInTheBridgeContract() {
        val contract = BlackBoxBridge.contractFor(
            authority, 4, "com.whatsapp", node("Paris", tls = true),
            RouteGeo(
                countryIso = "fr",
                city = "Paris",
                region = "IDF",
                latitude = 48.8,
                longitude = 2.3,
                timezoneId = "Europe/Paris",
                locale = "fr-FR"
            )
        )
        assertTrue(contract.tls)
        assertEquals("fr-FR", contract.locale)
        assertEquals("Europe/Paris", contract.timezoneId)
        assertEquals(48.8, contract.latitude!!, 0.001)
        assertEquals(2.3, contract.longitude!!, 0.001)
        assertEquals("127.0.0.1", contract.localHost)
        assertTrue(contract.localPort in 20000..27999)
        assertEquals("sp", contract.socksUser)
        assertTrue(contract.socksPassword.isNotBlank())
    }

    @Test
    fun localeFollowsTheExitCountry() {
        assertEquals("fr-FR", RouteLocale.forCountry("fr"))
        assertEquals("en-GB", RouteLocale.forCountry("uk"))
    }

    @Test
    fun sharedServerUsernameOrPackageIdIsRejected() {
        val left = AssignmentRules.parse(tag(1, "com.instagram.android"))!!
        val right = AssignmentRules.parse(tag(2, "com.whatsapp"))!!
        val violations = AssignmentRules.sharedUpstreamViolations(
            listOf(
                left to node("A", user = "package-349957-sessionid-aaa"),
                right to node("B", user = "package-349957-sessionid-bbb", server = "other.example")
            )
        )
        assertEquals(1, violations.size)

        val sameSession = AssignmentRules.sharedUpstreamViolations(
            listOf(
                left to node("A", user = "package-1-sessionid-aaa"),
                right to node("C", user = "alice", server = "gw.example", port = 1080)
                    .copy(username = "alice")
            )
        )
        assertTrue(sameSession.isEmpty())

        val sameGateway = AssignmentRules.sharedUpstreamViolations(
            listOf(
                left to node("A", user = "alice"),
                right to node("B", user = "alice")
            )
        )
        assertEquals(1, sameGateway.size)
    }

    @Test
    fun sharedGmsUserMayKeepOneNode() {
        val user = "$authority:1"
        val left = AssignmentRules.parse(tag(1, "com.instagram.android"))!!
        val right = AssignmentRules.parse(tag(1, "com.android.chrome"))!!
        val node = node("Only")
        val violations = AssignmentRules.sharedUpstreamViolations(
            listOf(left to node, right to node),
            sharedGmsUsers = setOf(user)
        )
        assertTrue(violations.isEmpty())
    }

    @Test
    fun sensitiveSetCanIncludeMoreThanInstagramAndWhatsApp() {
        val tags = listOf(tag(0, "org.telegram.messenger"), tag(0, "com.instagram.android"))
        assertTrue(AssignmentRules.sensitiveCoLocationsFromTags(tags).isEmpty())
        val custom = AssignmentRules.SENSITIVE + "org.telegram.messenger"
        assertEquals(listOf("$authority:0"), AssignmentRules.sensitiveCoLocationsFromTags(tags, custom))
    }

    @Test
    fun scanDoesNotClaimGuardsThatWereNotObserved() {
        assertEquals("Kernel ID not confirmed by Blackbox", ScanReport.kernelLine(false))
        assertEquals("Kernel ID isolated", ScanReport.kernelLine(true))
        assertEquals("Sensor calibration not confirmed by Blackbox", ScanReport.sensorLine(false))
        assertTrue(ScanReport.identityLine(true).startsWith("Launch blocked:"))
        assertFalse(ScanReport.identityLine(false).contains("Launch blocked"))
    }

    @Test
    fun crashReportOmitsDeviceAndCloneIdsUnlessOptedIn() {
        val hidden = CrashReporter.buildFailureReport(
            kind = "route_down",
            detail = "proxy unreachable",
            version = "9.3",
            androidRelease = "14",
            device = "Acme Phone",
            includeDevice = false,
            extras = mapOf("pkg" to "com.instagram.android", "userId" to 3, "proxyType" to "socks5")
        )
        assertFalse(hidden.has("device"))
        assertFalse(hidden.has("pkg"))
        assertFalse(hidden.has("userId"))
        assertEquals("socks5", hidden.getString("proxyType"))

        val shown = CrashReporter.buildFailureReport(
            kind = "route_down",
            detail = "proxy unreachable",
            version = "9.3",
            androidRelease = "14",
            device = "Acme Phone",
            includeDevice = true,
            extras = mapOf("pkg" to "com.instagram.android", "userId" to 3)
        )
        assertEquals("Acme Phone", shown.getString("device"))
        assertEquals(3, shown.getInt("userId"))
    }

    @Test
    fun cloudBlobRoundTripsAndStillReadsLegacyPlaintext() {
        val key = CloudBackupCrypto.keyFromBytes(ByteArray(32) { (it + 1).toByte() })
        val sealed = CloudBackupCrypto.seal(mapOf("proxies.json" to "{\"nodes\":[]}"), key)
        val opened = CloudBackupCrypto.open(sealed, key)
        assertFalse(opened.legacyPlaintext)
        assertEquals("{\"nodes\":[]}", opened.files["proxies.json"])

        val legacy = """{"v":1,"files":{"profiles.json":"[]"}}"""
        val migrated = CloudBackupCrypto.open(legacy, key)
        assertTrue(migrated.legacyPlaintext)
        assertEquals("[]", migrated.files["profiles.json"])
    }

    @Test
    fun engineMergeKeepsEveryProfileCloneRoute() {
        val active = RoutingConfig()
        val other = RoutingConfig()
        other.nodes.add(node("Berlin"))
        other.bbMap[tag(9, "com.whatsapp")] = "Berlin"
        val merged = EngineRoutes.merge(active, listOf(other))
        assertEquals("Berlin", merged.bbMap[tag(9, "com.whatsapp")])
        assertEquals("Berlin", merged.nodes.single().name)
    }

    private fun tag(userId: Int, pkg: String) = "bb:$authority:$userId:$pkg"

    private fun node(
        name: String,
        tls: Boolean = false,
        user: String = "package-1-sessionid-abc",
        server: String = "gw.example",
        port: Int = 1080
    ) = ProxyNode(
        name = name,
        type = "socks5",
        server = server,
        port = port,
        username = user,
        tls = tls
    )
}
