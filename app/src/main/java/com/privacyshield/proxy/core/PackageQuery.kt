package com.privacyshield.proxy.core

/**
 * Package queries and VPN app filters are bound to the calling Android user.
 * [FLAGS] must stay 0. [android.content.pm.PackageManager.MATCH_ANY_USER] would mix profiles.
 */
object PackageQuery {
    const val FLAGS = 0

    fun sameUser(uid: Int, userId: Int): Boolean = AndroidProfile.userIdOf(uid) == userId
}
