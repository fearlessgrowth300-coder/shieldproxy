package com.privacyshield.proxy.core

/**
 * What may stop a clone from opening.
 *
 * Blackbox reports `Isolation guard failed: sensor` when its per-clone sensor
 * calibration hook is not active. That is a fingerprint warning. It is not a
 * direct-IP or cross-clone network leak, so it must not keep the app closed
 * when the route id and exit IP already match.
 */
object CloneLaunchGate {
    const val SENSOR_ONLY = "Isolation guard failed: sensor"
    const val SENSOR_WARNING =
        "Sensor calibration isn't confirmed. Opening anyway. This is not a network leak."

    data class Decision(val block: String?, val warning: String?)

    fun isSensorOnly(error: String): Boolean =
        error.trim().equals(SENSOR_ONLY, ignoreCase = true)

    fun decide(
        ok: Boolean,
        routeId: String,
        exitIp: String,
        expectedExitIp: String,
        error: String,
        state: String
    ): Decision {
        val exitOk = exitIp.isNotBlank() && exitIp.equals(expectedExitIp, ignoreCase = true)
        if (routeId.isNotBlank() && exitOk && (ok || isSensorOnly(error))) {
            val warning = if (!ok && isSensorOnly(error)) SENSOR_WARNING else null
            return Decision(block = null, warning = warning)
        }
        val reason = error.ifBlank {
            if (exitIp.isNotBlank() && !exitOk) {
                "In-guest exit $exitIp did not match the proxy exit $expectedExitIp."
            } else {
                "Route verification failed (${state.ifBlank { "unknown state" }})."
            }
        }
        return Decision(block = reason, warning = null)
    }
}
