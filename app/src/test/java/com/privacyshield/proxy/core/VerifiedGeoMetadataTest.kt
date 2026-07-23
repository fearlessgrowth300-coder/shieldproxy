package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VerifiedGeoMetadataTest {
    @Test
    fun acceptsMatchingTlsMetadata() {
        val metadata = ProxyTester.parseMetadata(
            """{
              "success":true,
              "ip":"203.0.113.9",
              "country_code":"GB",
              "region":"England",
              "city":"Manchester",
              "latitude":53.4808,
              "longitude":-2.2426,
              "timezone":{"id":"Europe/London"},
              "connection":{"isp":"Example Mobile"}
            }""",
            "203.0.113.9"
        )

        assertEquals("gb", metadata.countryIso)
        assertEquals("Manchester", metadata.city)
        assertEquals(53.4808, metadata.latitude!!, 0.000001)
        assertEquals(-2.2426, metadata.longitude!!, 0.000001)
        assertEquals("Europe/London", metadata.timezoneId)
        assertEquals("📶 Mobile", metadata.type)
    }

    @Test
    fun rejectsMetadataForDifferentExitIp() {
        val metadata = ProxyTester.parseMetadata(
            """{"success":true,"ip":"198.51.100.2","country_code":"US"}""",
            "203.0.113.9"
        )

        assertEquals("", metadata.countryIso)
        assertNull(metadata.latitude)
    }

    @Test
    fun dropsInvalidCoordinatesCountryAndTimezone() {
        val metadata = ProxyTester.parseMetadata(
            """{
              "success":true,
              "ip":"203.0.113.9",
              "country_code":"USA",
              "latitude":1000,
              "longitude":-1000,
              "timezone":{"id":"Not/A_Real_Zone"}
            }""",
            "203.0.113.9"
        )

        assertEquals("", metadata.countryIso)
        assertNull(metadata.latitude)
        assertNull(metadata.longitude)
        assertEquals("", metadata.timezoneId)
    }
}
