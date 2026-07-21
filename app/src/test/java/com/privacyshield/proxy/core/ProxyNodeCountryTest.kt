package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Test

class ProxyNodeCountryTest {
    @Test
    fun readsSoaxCountryHint() {
        val node = ProxyNode(
            name = "mobile",
            type = "http",
            server = "proxy.example",
            port = 5000,
            username = "package-1-country-us-region-florida-sessionid-test"
        )

        assertEquals("us", node.countryIsoHint())
    }

    @Test
    fun normalizesUkCountryHint() {
        val node = ProxyNode(
            name = "mobile",
            type = "http",
            server = "proxy.example",
            port = 5000,
            username = "package-1-country-uk-sessionid-test"
        )

        assertEquals("gb", node.countryIsoHint())
    }

    @Test
    fun missingCountryDoesNotGuess() {
        val node = ProxyNode("plain", "http", "proxy.example", 5000)

        assertEquals("", node.countryIsoHint())
    }
}
