package com.privacyshield.proxy.core

/**
 * Wording for the privacy scan. A line is emitted only when this process actually observed it.
 */
object ScanReport {
    fun kernelLine(kernelGuard: Boolean): String =
        if (kernelGuard) "Kernel ID isolated" else "Kernel ID not confirmed by Blackbox"

    fun sensorLine(sensorGuard: Boolean): String =
        if (sensorGuard) "Sensor calibration isolated" else "Sensor calibration not confirmed by Blackbox"

    fun identityLine(collision: Boolean): String =
        if (collision) "Launch blocked: this Blackbox user shares an identity digest with another user"
        else "Identity digest is distinct from the other users scanned on this phone"

    fun routeLine(exitMatched: Boolean, exitIp: String): String =
        if (exitMatched) "In-guest exit $exitIp matches the proxy exit"
        else "In-guest exit was not proven to match the proxy exit ($exitIp)"
}

/**
 * Remembers identity digests returned by Blackbox. A digest seen on two virtual users blocks
 * launch of the later user. Digests are not raw device ids.
 */
object CloneIdentityBook {
    private const val PREFS = "clone_identity_book"
    private const val BLOCKED = "blocked_users"

    fun collides(known: Map<String, String>, userKey: String, digest: String): Boolean {
        if (digest.isBlank()) return false
        val owner = known[digest] ?: return false
        return owner != userKey
    }

    fun isBlocked(ctx: android.content.Context, userKey: String): Boolean =
        ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
            .getStringSet(BLOCKED, emptySet()).orEmpty().contains(userKey)

    fun block(ctx: android.content.Context, userKeys: Collection<String>) {
        val prefs = ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
        val next = prefs.getStringSet(BLOCKED, emptySet()).orEmpty().toMutableSet()
        next.addAll(userKeys)
        prefs.edit().putStringSet(BLOCKED, next).apply()
    }

    /** @return true when [digest] is already owned by a different user. The book is updated either way. */
    fun remember(ctx: android.content.Context, userKey: String, digest: String): Boolean {
        if (digest.isBlank()) return false
        val prefs = ctx.getSharedPreferences(PREFS, android.content.Context.MODE_PRIVATE)
        val known = HashMap<String, String>()
        for ((storedDigest, owner) in prefs.all) {
            if (owner is String) known[storedDigest] = owner
        }
        val collision = collides(known, userKey, digest)
        if (!collision) prefs.edit().putString(digest, userKey).apply()
        return collision
    }
}
