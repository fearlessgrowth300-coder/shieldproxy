package com.privacyshield.proxy.core

/**
 * The VPN process reads one [RoutingConfig]. Clone routes can live on several saved lists,
 * and every one of them needs a listener while the engine is up. Phone-app rules stay those
 * of the active list. Clone maps and the nodes they name are unioned in.
 */
object EngineRoutes {
    fun merge(active: RoutingConfig, others: List<RoutingConfig>): RoutingConfig {
        val merged = RoutingConfig.fromJson(active.toJson())
        for (other in others) {
            for ((tag, node) in other.bbMap) {
                if (tag !in merged.bbMap) merged.bbMap[tag] = node
            }
            for (node in other.nodes) {
                if (node.name in merged.bbMap.values && merged.nodes.none { it.name == node.name }) {
                    merged.nodes.add(node)
                }
            }
        }
        return merged
    }
}
