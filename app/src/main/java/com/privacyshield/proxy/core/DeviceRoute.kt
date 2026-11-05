package com.privacyshield.proxy.core

/**
 * What the phone VPN is allowed to use as its catch-all.
 * A clone list is not a device route: its proxy belongs to that clone's listener only.
 */
object DeviceRoute {
    fun isCloneList(cfg: RoutingConfig): Boolean =
        cfg.appMap.isEmpty() && cfg.bbMap.isNotEmpty()

    fun phoneConfig(cfg: RoutingConfig): RoutingConfig {
        if (!isCloneList(cfg) || cfg.finalTarget == "DIRECT") return cfg
        val copy = RoutingConfig.fromJson(cfg.toJson())
        copy.finalTarget = "DIRECT"
        return copy
    }

    /** Empty when the active list is only clones, so the header does not name their proxy. */
    fun headerSuffix(profileName: String?, cfg: RoutingConfig?): String {
        if (profileName.isNullOrBlank() || cfg == null || isCloneList(cfg)) return ""
        return " · $profileName"
    }
}
