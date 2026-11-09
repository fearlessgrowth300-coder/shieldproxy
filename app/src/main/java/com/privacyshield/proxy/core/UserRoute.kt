package com.privacyshield.proxy.core

/**
 * One Blackbox user has one route. Play Store and Google services in that user
 * are not separate exits; they use the same listener as the app the user assigned.
 */
object UserRoute {
    val SHARED_PACKAGES = listOf(
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.google.android.gsf.login",
        "com.android.vending",
        "com.google.android.backuptransport",
        "com.google.android.backup",
        "com.google.android.configupdater",
        "com.google.android.syncadapters.contacts",
        "com.google.android.syncadapters.calendar",
        "com.google.android.feedback",
        "com.google.android.onetimeinitializer",
        "com.google.android.partnersetup",
        "com.google.android.setupwizard"
    )

    /** Users whose saved packages name more than one node. Those users are not one route. */
    fun conflicts(bbMap: Map<String, String>): List<String> {
        val nodes = LinkedHashMap<String, MutableSet<String>>()
        for ((tag, node) in bbMap) {
            val parsed = AssignmentRules.parse(tag) ?: continue
            val key = "${parsed.authority}:${parsed.userId}"
            nodes.getOrPut(key) { LinkedHashSet() }.add(node)
        }
        return nodes.filterValues { it.size > 1 }.keys.sorted()
    }
}

/**
 * What a privacy scan can decide without starting a Blackbox guest.
 * Starting a guest to probe it is what left the scan on "Scanning…" and spawned
 * a new process every few seconds.
 */
object RouteLeakCheck {
    data class Verdict(val pass: Boolean, val lines: List<String>)

    fun assess(
        exitIp: String,
        realIp: String?,
        listenerOpen: Boolean,
        userConflict: Boolean,
        containersExcluded: Boolean,
        privateDnsDirect: Boolean,
        ipv6Blocked: Boolean,
        stunBlocked: Boolean,
        killSwitchOn: Boolean
    ): Verdict {
        val lines = ArrayList<String>()
        var pass = true
        if (userConflict) {
            pass = false
            lines.add("FAIL this Blackbox user is assigned more than one proxy")
        }
        if (exitIp.isBlank()) {
            pass = false
            lines.add("FAIL the assigned proxy did not return an exit IP")
        } else if (!realIp.isNullOrBlank() && exitIp.equals(realIp, ignoreCase = true)) {
            pass = false
            lines.add("FAIL exit $exitIp is the phone's real IP")
        } else {
            lines.add("PASS exit $exitIp is not the phone IP")
        }
        if (!listenerOpen) {
            pass = false
            lines.add("FAIL the per-user listener is not accepting connections")
        } else {
            lines.add("PASS the per-user listener is open")
        }
        if (!containersExcluded || !privateDnsDirect) {
            pass = false
            lines.add("FAIL strict Private DNS would be captured or blackholed")
        } else {
            lines.add("PASS containers stay outside the VPN, so Private DNS is not rewritten; clone DNS is the per-user SOCKS listener")
        }
        if (!stunBlocked) {
            pass = false
            lines.add("FAIL UDP 443 is not rejected, so a STUN/WebRTC path can leave the tunnel")
        } else {
            lines.add("PASS QUIC/STUN on UDP 443 is rejected inside the tunnel")
        }
        if (!ipv6Blocked) {
            pass = false
            lines.add("FAIL IPv6 is not rejected")
        } else {
            lines.add("PASS IPv6 destinations are rejected")
        }
        if (!killSwitchOn) {
            pass = false
            lines.add("FAIL the kill switch is off, so a dropped route does not fail closed")
        } else {
            lines.add("PASS a dropped route fails closed")
        }
        return Verdict(pass, lines)
    }

    /** Routes that observed the same exit IP. A shared exit is a cross-route leak. */
    fun sharedExits(exits: Map<String, String>): Set<String> {
        return exits.values
            .filter { it.isNotBlank() }
            .groupBy { it.lowercase() }
            .filterValues { it.size > 1 }
            .keys
            .toSet()
    }
}
