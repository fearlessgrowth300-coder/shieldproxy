package com.privacyshield.proxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AssignmentRulesPolicyTest {
    private val authority = "top.niunaijun.blackbox.bridge"

    private fun tag(userId: Int, pkg: String) = "bb:$authority:$userId:$pkg"

    @Test
    fun parseRejectsMalformedTagsAndKeepsTheExactUserIdentity() {
        assertEquals("$authority:7", AssignmentRules.parse(tag(7, "com.instagram.android"))?.user)
        assertEquals(null, AssignmentRules.parse("com.instagram.android"))
        assertEquals(null, AssignmentRules.parse("bb:$authority:not-a-user:com.instagram.android"))
        assertEquals(null, AssignmentRules.parse("bb::1:com.instagram.android"))
    }

    @Test
    fun instagramAndWhatsAppCannotShareOneBlackBoxUser() {
        val violations = AssignmentRules.sensitiveCoLocationsFromTags(
            listOf(tag(0, "com.instagram.android"), tag(0, "com.whatsapp"))
        )
        assertEquals(listOf("$authority:0"), violations)
    }

    @Test
    fun sensitiveAccountsInDifferentUsersRemainIndependent() {
        val violations = AssignmentRules.sensitiveCoLocationsFromTags(
            listOf(tag(0, "com.instagram.android"), tag(1, "com.whatsapp"))
        )
        assertTrue(violations.isEmpty())
    }

    @Test
    fun sharedGmsUserCannotUseTwoProxyNodes() {
        val user = "$authority:0"
        val violations = AssignmentRules.gmsProxyInconsistenciesFromAssignments(
            linkedMapOf(
                tag(0, "com.instagram.android") to "Minneapolis",
                tag(0, "com.google.android.gm") to "Atlanta"
            ),
            setOf(user)
        )
        assertEquals(1, violations.size)
        assertEquals(user, violations.single().user)
        assertEquals(setOf("Minneapolis", "Atlanta"), violations.single().nodes)
    }

    @Test
    fun sharedGmsUserMayUseOneCommonProxyAcrossApps() {
        val violations = AssignmentRules.gmsProxyInconsistenciesFromAssignments(
            linkedMapOf(
                tag(0, "com.instagram.android") to "Minneapolis",
                tag(0, "com.google.android.gm") to "Minneapolis"
            ),
            setOf("$authority:0")
        )
        assertTrue(violations.isEmpty())
    }

    @Test
    fun nonSharedUsersAreNotRestrictedByTheGmsRule() {
        val violations = AssignmentRules.gmsProxyInconsistenciesFromAssignments(
            linkedMapOf(
                tag(0, "com.example.one") to "Minneapolis",
                tag(0, "com.example.two") to "Atlanta"
            ),
            emptySet()
        )
        assertTrue(violations.isEmpty())
    }
}
