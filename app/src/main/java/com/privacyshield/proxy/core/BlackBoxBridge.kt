package com.privacyshield.proxy.core

import android.content.Context
import android.net.Uri

/** One clone (User) exposed by a specific BlackBox variant's bridge. */
data class BbClone(val authority: String, val userId: Int, val pkg: String, val label: String)
data class BbConfiguredRoute(val authority: String, val userId: Int, val pkg: String) {
    val tag: String get() = "bb:$authority:$userId:$pkg"
}

data class BbProxyAssignment(
    val ok: Boolean, val routeId: String = "", val state: String = "", val error: String = ""
)

data class BbWarmResult(
    val ok: Boolean, val alreadyRunning: Boolean = false, val error: String = ""
)

data class BbRouteVerification(
    val ok: Boolean, val routeId: String = "", val exitIp: String = "",
    val state: String = "", val error: String = "", val latencyMs: Long = 0L,
    val kernelGuard: Boolean = false, val sensorGuard: Boolean = false
)

data class BbIdentityStatus(
    val ok: Boolean, val digest: String = "", val error: String = ""
)

data class BbUserSecurityState(
    val ok: Boolean,
    val sharedGmsActive: Boolean = false,
    val gmsInstalled: Boolean = false,
    val keepAliveEnabled: Boolean = false,
    val error: String = ""
)

/** Non-secret result of the signed app-to-app readiness handshake. */
data class BbConnectionStatus(
    val reachable: Boolean,
    val ready: Boolean = false,
    val sameAccount: Boolean = false,
    val versionName: String = "",
    val driveConnected: Boolean = false,
    val error: String = ""
)

/**
 * BlackBox ships under several package names (build variants) — orig/nova/vault/prism — each
 * exposing its proxy bridge under authority "<applicationId>.bridge". A user may have installed
 * ONE of them, or several at once. ShieldProxy talks to whichever are present and shows the
 * clones from all of them, tagging each clone with its source authority so proxy assignments go
 * back to the correct variant's bridge.
 *
 * Keep CANDIDATES in sync with app/build.gradle productFlavors in the BlackBox repo.
 */
object BlackBoxBridge {

    private val CANDIDATES = listOf(
        "top.niunaijun.blackbox.bridge",  // orig  (BlackBox)
        "com.novspace.box.bridge",        // nova  (NovSpace)
        "app.cloudvault.multi.bridge",    // vault (CloudVault)
        "io.prismhub.clone.bridge"        // prism (Prism)
    )

    /** Friendly label for a bridge authority, for display in the picker. */
    fun variantName(authority: String): String = when (authority) {
        "top.niunaijun.blackbox.bridge" -> "BlackBox"
        "com.novspace.box.bridge" -> "NovSpace"
        "app.cloudvault.multi.bridge" -> "CloudVault"
        "io.prismhub.clone.bridge" -> "Prism"
        else -> "BlackBox"
    }

    fun baseFor(authority: String): Uri = Uri.parse("content://$authority")

    /** Every installed variant bridge that actually answers a query, in candidate order. */
    fun installedAuthorities(ctx: Context): List<String> {
        val cr = ctx.contentResolver
        val out = ArrayList<String>()
        for (auth in CANDIDATES) {
            try {
                // A present provider returns a Cursor (even when empty); an absent one throws/nulls.
                cr.query(Uri.parse("content://$auth/apps"), null, null, null, null)?.use {
                    out.add(auth)
                }
            } catch (_: Exception) {
                // not installed — skip
            }
        }
        return out
    }

    /** First installed variant, or null. Kept for single-target callers. */
    fun authority(ctx: Context): String? = installedAuthorities(ctx).firstOrNull()

    fun base(ctx: Context): Uri? = authority(ctx)?.let { baseFor(it) }

    /** List only user-facing per-clone route keys. Credentials and shared-GMS copies never cross
     * the bridge. Used to let the user review routes that are no longer claimed by any list. */
    fun configuredRoutes(ctx: Context): List<BbConfiguredRoute> {
        val out = ArrayList<BbConfiguredRoute>()
        for (auth in installedAuthorities(ctx)) {
            try {
                ctx.contentResolver.query(
                    Uri.withAppendedPath(baseFor(auth), "routes"), null, null, null, null
                )?.use { c ->
                    while (c.moveToNext()) {
                        val userId = c.getInt(0)
                        val pkg = c.getString(1)
                        if (userId >= 0 && !pkg.isNullOrBlank()) {
                            out.add(BbConfiguredRoute(auth, userId, pkg))
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
        return out.distinctBy { it.tag }
    }

    /** Verify that a signed BlackBox variant is unlocked and belongs to this account. */
    fun connectionStatus(ctx: Context): BbConnectionStatus {
        val localOwner = VaultKeyStore.ownerHash(ctx)
        var reachedLockedProvider = false
        for (auth in CANDIDATES) {
            try {
                val r = ctx.contentResolver.call(baseFor(auth), "status", null, null)
                    ?: continue
                reachedLockedProvider = true
                val remoteOwner = r.getString("ownerHash").orEmpty()
                val ready = r.getBoolean("ok")
                val same = ready && !localOwner.isNullOrBlank() && localOwner == remoteOwner
                return BbConnectionStatus(
                    reachable = true,
                    ready = ready,
                    sameAccount = same,
                    versionName = r.getString("versionName").orEmpty(),
                    driveConnected = r.getBoolean("driveConnected"),
                    error = when {
                        !ready -> "BlackBox is locked. Sign in there, then verify again."
                        !same -> "The apps are signed in to different accounts."
                        else -> ""
                    }
                )
            } catch (_: SecurityException) {
                // Installed with a different signing certificate: never treat it as connected.
            } catch (_: Exception) {
                // This variant is not installed or its provider is unavailable.
            }
        }
        return BbConnectionStatus(
            reachable = reachedLockedProvider,
            error = "BlackBox is not installed, not reachable, or is not signed by the trusted key."
        )
    }

    /** Persist one exact node for one exact clone. BlackBox stops an existing process so it
     * cannot keep using stale credentials. The returned routeId is safe to display/store and
     * binds the later guest-process verification to this assignment. */
    fun setCloneProxy(
        ctx: Context, authority: String, userId: Int, pkg: String, node: ProxyNode,
        verifiedCountryIso: String = "", verifiedCity: String = "",
        verifiedRegion: String = "", verifiedLatitude: Double? = null,
        verifiedLongitude: Double? = null, verifiedTimezoneId: String = ""
    ): BbProxyAssignment = try {
        val extras = android.os.Bundle().apply {
            putInt("userId", userId); putString("pkg", pkg)
            putString("type", node.type); putString("server", node.server); putInt("port", node.port)
            putString("username", node.username); putString("password", node.password)
            putString("countryIso", verifiedCountryIso.ifBlank { node.countryIsoHint() })
            putString("city", verifiedCity); putString("region", verifiedRegion)
            if (verifiedLatitude != null) putDouble("latitude", verifiedLatitude)
            if (verifiedLongitude != null) putDouble("longitude", verifiedLongitude)
            putString("timezoneId", verifiedTimezoneId)
        }
        val r = ctx.contentResolver.call(baseFor(authority), "setProxy", null, extras)
        BbProxyAssignment(
            ok = r?.getBoolean("ok") == true,
            routeId = r?.getString("routeId").orEmpty(),
            state = r?.getString("state").orEmpty(),
            error = r?.getString("err").orEmpty()
        )
    } catch (e: Exception) {
        BbProxyAssignment(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Remove one exact clone assignment. BlackBox also stops that virtual app and resynchronizes
     * shared GMS, so an edited profile cannot leave an orphaned route active in the old user. */
    fun clearCloneProxy(
        ctx: Context, authority: String, userId: Int, pkg: String
    ): BbProxyAssignment = try {
        val extras = android.os.Bundle().apply {
            putInt("userId", userId)
            putString("pkg", pkg)
        }
        val r = ctx.contentResolver.call(baseFor(authority), "clearProxy", null, extras)
        BbProxyAssignment(
            ok = r?.getBoolean("ok") == true,
            state = r?.getString("state").orEmpty(),
            error = r?.getString("err").orEmpty()
        )
    } catch (e: Exception) {
        BbProxyAssignment(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Read-only phase of a profile save. No BlackBox credential file or process is changed. */
    fun canSetCloneProxy(
        ctx: Context, authority: String, userId: Int, pkg: String, node: ProxyNode
    ): BbProxyAssignment = try {
        val extras = android.os.Bundle().apply {
            putInt("userId", userId); putString("pkg", pkg)
            putString("type", node.type); putString("server", node.server); putInt("port", node.port)
            putString("username", node.username); putString("password", node.password)
            putString("countryIso", node.countryIsoHint())
        }
        val r = ctx.contentResolver.call(baseFor(authority), "canSetProxy", null, extras)
        BbProxyAssignment(
            ok = r?.getBoolean("ok") == true,
            state = r?.getString("state").orEmpty(),
            error = r?.getString("err").orEmpty()
        )
    } catch (e: Exception) {
        BbProxyAssignment(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Start only the isolated guest process. Proxy setup runs during process initialization,
     * before the cloned app's Application is created or its foreground activity is shown. */
    fun prepareRoute(ctx: Context, authority: String, userId: Int, pkg: String): BbProxyAssignment = try {
        val extras = android.os.Bundle().apply { putInt("userId", userId); putString("pkg", pkg) }
        val r = ctx.contentResolver.call(baseFor(authority), "prepareRoute", null, extras)
        BbProxyAssignment(
            ok = r?.getBoolean("ok") == true,
            routeId = r?.getString("routeId").orEmpty(),
            state = r?.getString("state").orEmpty(),
            error = r?.getString("err").orEmpty()
        )
    } catch (e: Exception) {
        BbProxyAssignment(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Compare virtual-device identities without exporting any raw identifier from BlackBox. */
    fun identityStatus(ctx: Context, authority: String, userId: Int): BbIdentityStatus = try {
        val extras = android.os.Bundle().apply { putInt("userId", userId) }
        val r = ctx.contentResolver.call(baseFor(authority), "identityStatus", null, extras)
        BbIdentityStatus(
            ok = r?.getBoolean("ok") == true,
            digest = r?.getString("identityDigest").orEmpty(),
            error = r?.getString("err").orEmpty()
        )
    } catch (e: Exception) {
        BbIdentityStatus(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Ask the signed BlackBox bridge whether this exact virtual user shares GMS. A failed query
     * is intentionally distinguishable from a verified `false`, so assignment validation can
     * fail closed rather than allowing an unsafe second proxy. */
    fun userSecurityState(
        ctx: Context, authority: String, userId: Int
    ): BbUserSecurityState = try {
        val extras = android.os.Bundle().apply { putInt("userId", userId) }
        val r = ctx.contentResolver.call(baseFor(authority), "userSecurityState", null, extras)
        BbUserSecurityState(
            ok = r?.getBoolean("ok") == true,
            sharedGmsActive = r?.getBoolean("sharedGmsActive") == true,
            gmsInstalled = r?.getBoolean("gmsInstalled") == true,
            keepAliveEnabled = r?.getBoolean("keepAliveEnabled") == true,
            error = r?.getString("err").orEmpty()
        )
    } catch (e: Exception) {
        BbUserSecurityState(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Prove the live guest has the assigned route and that its own TCP request exits on the IP
     * independently observed through the selected ShieldProxy node. */
    fun verifyRoute(
        ctx: Context, authority: String, userId: Int, pkg: String, expectedExitIp: String
    ): BbRouteVerification = try {
        val extras = android.os.Bundle().apply {
            putInt("userId", userId); putString("pkg", pkg)
            putString("expectedExitIp", expectedExitIp)
        }
        val r = ctx.contentResolver.call(baseFor(authority), "verifyRoute", null, extras)
        BbRouteVerification(
            ok = r?.getBoolean("ok") == true,
            routeId = r?.getString("routeId").orEmpty(),
            exitIp = r?.getString("exitIp").orEmpty(),
            state = r?.getString("state").orEmpty(),
            error = r?.getString("err").orEmpty(),
            latencyMs = r?.getLong("latencyMs") ?: 0L,
            kernelGuard = r?.getBoolean("kernelGuard") == true,
            sensorGuard = r?.getBoolean("sensorGuard") == true
        )
    } catch (e: Exception) {
        BbRouteVerification(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Atomic launch gate: persist the exact node, stop stale processes, initialize the guest
     * route, and compare its observed exit IP before returning success. */
    fun assignAndVerifyRoute(
        ctx: Context, authority: String, userId: Int, pkg: String,
        node: ProxyNode, expectedExitIp: String, verifiedCountryIso: String = "",
        verifiedCity: String = "", verifiedRegion: String = "",
        verifiedLatitude: Double? = null, verifiedLongitude: Double? = null,
        verifiedTimezoneId: String = ""
    ): BbRouteVerification = try {
        val extras = android.os.Bundle().apply {
            putInt("userId", userId); putString("pkg", pkg)
            putString("type", node.type); putString("server", node.server); putInt("port", node.port)
            putString("username", node.username); putString("password", node.password)
            putString("expectedExitIp", expectedExitIp)
            putString("countryIso", verifiedCountryIso.ifBlank { node.countryIsoHint() })
            putString("city", verifiedCity); putString("region", verifiedRegion)
            if (verifiedLatitude != null) putDouble("latitude", verifiedLatitude)
            if (verifiedLongitude != null) putDouble("longitude", verifiedLongitude)
            putString("timezoneId", verifiedTimezoneId)
        }
        val r = ctx.contentResolver.call(baseFor(authority), "assignAndVerifyRoute", null, extras)
        BbRouteVerification(
            ok = r?.getBoolean("ok") == true,
            routeId = r?.getString("routeId").orEmpty(),
            exitIp = r?.getString("exitIp").orEmpty(),
            state = r?.getString("state").orEmpty(),
            error = r?.getString("err").orEmpty(),
            latencyMs = r?.getLong("latencyMs") ?: 0L,
            kernelGuard = r?.getBoolean("kernelGuard") == true,
            sensorGuard = r?.getBoolean("sensorGuard") == true
        )
    } catch (e: Exception) {
        BbRouteVerification(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Force-close only when a verified route identity becomes unsafe. */
    fun stopClone(ctx: Context, authority: String, userId: Int, pkg: String): Boolean = try {
        val extras = android.os.Bundle().apply { putInt("userId", userId); putString("pkg", pkg) }
        val r = ctx.contentResolver.call(baseFor(authority), "stopApp", null, extras)
        r?.getBoolean("ok") == true
    } catch (_: Exception) { false }

    /**
     * Restart a killed clone's own push connection, with no visible UI.
     *
     * OEM power managers SIGKILL the whole container process group when its task leaves Recents,
     * which takes the guest's push process with it (Instagram's :fbns, WhatsApp's socket) — so the
     * user simply stops receiving messages. Nothing inside the container can repair that, because it
     * dies in the same kill. ShieldProxy is a separate package and uid, so it survives; calling this
     * provider is itself what brings the container back up.
     */
    fun warmClone(ctx: Context, authority: String, userId: Int, pkg: String): BbWarmResult = try {
        val extras = android.os.Bundle().apply { putInt("userId", userId); putString("pkg", pkg) }
        val r = ctx.contentResolver.call(baseFor(authority), "warmGuest", null, extras)
        if (r == null) BbWarmResult(false, error = "The container did not respond")
        else BbWarmResult(
            r.getBoolean("ok"),
            r.getBoolean("alreadyRunning"),
            r.getString("err").orEmpty()
        )
    } catch (e: Exception) {
        BbWarmResult(false, error = e.message ?: e.javaClass.simpleName)
    }

    /** Is this clone's process currently alive? Lets the guard nag/kill only when in use. */
    fun isCloneRunning(ctx: Context, authority: String, userId: Int, pkg: String): Boolean = try {
        val extras = android.os.Bundle().apply { putInt("userId", userId); putString("pkg", pkg) }
        val r = ctx.contentResolver.call(baseFor(authority), "isRunning", null, extras)
        r?.getBoolean("running") == true
    } catch (_: Exception) { false }
}
