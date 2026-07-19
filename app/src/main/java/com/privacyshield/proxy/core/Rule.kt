package com.privacyshield.proxy.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * All rule matcher types supported by the Mihomo (Clash.Meta) engine that
 * this app exposes. The `clash` string is the exact keyword written to config.
 */
enum class RuleType(val clash: String, val isIp: Boolean = false) {
    DOMAIN("DOMAIN"),
    DOMAIN_SUFFIX("DOMAIN-SUFFIX"),
    DOMAIN_KEYWORD("DOMAIN-KEYWORD"),
    DOMAIN_REGEX("DOMAIN-REGEX"),
    IP_CIDR("IP-CIDR", isIp = true),
    IP_CIDR6("IP-CIDR6", isIp = true),
    IP_ASN("IP-ASN", isIp = true),
    GEOIP("GEOIP", isIp = true),
    GEOSITE("GEOSITE"),
    SRC_IP_CIDR("SRC-IP-CIDR", isIp = true),
    SRC_PORT("SRC-PORT"),
    DST_PORT("DST-PORT"),
    PROCESS_NAME("PROCESS-NAME"),
    PROCESS_PATH("PROCESS-PATH"),
    NETWORK("NETWORK"),          // tcp | udp
    UID("UID"),
    RULE_SET("RULE-SET");

    companion object {
        fun fromClash(s: String): RuleType? = entries.firstOrNull { it.clash == s }
    }
}

/** Boolean operator for a compound rule. */
enum class LogicOp { AND, OR, NOT }

/**
 * A routing rule. Either:
 *  - simple:  TYPE,payload,target
 *  - logical: AND,((T1,p1),(T2,p2)),target
 *  - match:   MATCH,target   (final catch-all)
 *
 * `target` is a node name, a proxy-group name, DIRECT, or REJECT.
 */
data class Rule(
    val target: String,
    val simpleType: RuleType? = null,
    val payload: String = "",
    val noResolve: Boolean = false,
    val logicOp: LogicOp? = null,
    val conditions: List<Condition> = emptyList(),
    val isMatch: Boolean = false
) {
    data class Condition(val type: RuleType, val payload: String) {
        fun toClash(): String = "(${type.clash},$payload)"
    }

    fun toClashLine(): String = when {
        isMatch -> "  - MATCH,$target"
        logicOp != null -> {
            val inner = conditions.joinToString(",") { it.toClash() }
            "  - ${logicOp.name},($inner),$target"
        }
        simpleType != null -> {
            val base = "  - ${simpleType.clash},$payload,$target"
            if (noResolve && simpleType.isIp) "$base,no-resolve" else base
        }
        else -> "  - MATCH,$target"
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("target", target)
        put("isMatch", isMatch)
        simpleType?.let { put("simpleType", it.name) }
        put("payload", payload)
        put("noResolve", noResolve)
        logicOp?.let { put("logicOp", it.name) }
        if (conditions.isNotEmpty()) put("conditions", JSONArray().apply {
            conditions.forEach { put(JSONObject().put("type", it.type.name).put("payload", it.payload)) }
        })
    }

    companion object {
        fun match(target: String) = Rule(target = target, isMatch = true)

        fun simple(type: RuleType, payload: String, target: String, noResolve: Boolean = false) =
            Rule(target = target, simpleType = type, payload = payload, noResolve = noResolve)

        fun logical(op: LogicOp, conditions: List<Condition>, target: String) =
            Rule(target = target, logicOp = op, conditions = conditions)

        fun fromJson(o: JSONObject): Rule {
            val conds = ArrayList<Condition>()
            o.optJSONArray("conditions")?.let {
                for (i in 0 until it.length()) {
                    val c = it.getJSONObject(i)
                    RuleType.valueOf(c.getString("type")).let { t -> conds.add(Condition(t, c.getString("payload"))) }
                }
            }
            return Rule(
                target = o.getString("target"),
                simpleType = o.optString("simpleType", "").takeIf { it.isNotEmpty() }?.let { RuleType.valueOf(it) },
                payload = o.optString("payload", ""),
                noResolve = o.optBoolean("noResolve", false),
                logicOp = o.optString("logicOp", "").takeIf { it.isNotEmpty() }?.let { LogicOp.valueOf(it) },
                conditions = conds,
                isMatch = o.optBoolean("isMatch", false)
            )
        }
    }
}

/**
 * Remote or local rule-set provider (Rule-Set Providers feature).
 * Referenced from a Rule with type RULE_SET and payload = provider name.
 */
data class RuleProvider(
    val name: String,
    val type: String = "http",          // http | file
    val behavior: String = "classical", // domain | ipcidr | classical
    val url: String = "",
    val path: String = "",
    val format: String = "yaml",         // yaml | text | mrs
    val intervalSec: Int = 86400
) {
    fun toClashYaml(): String {
        val sb = StringBuilder()
        val p = path.ifBlank { "./providers/$name.${if (format == "mrs") "mrs" else "yaml"}" }
        sb.append("  ").append(name).append(":\n")
        sb.append("    type: ").append(type).append("\n")
        sb.append("    behavior: ").append(behavior).append("\n")
        if (type == "http" && url.isNotBlank()) sb.append("    url: ").append(ProxyNode.quote(url)).append("\n")
        sb.append("    format: ").append(format).append("\n")
        sb.append("    path: ").append(p).append("\n")
        sb.append("    interval: ").append(intervalSec).append("\n")
        return sb.toString()
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name); put("type", type); put("behavior", behavior)
        put("url", url); put("path", path); put("format", format); put("intervalSec", intervalSec)
    }

    companion object {
        fun fromJson(o: JSONObject) = RuleProvider(
            name = o.getString("name"),
            type = o.optString("type", "http"),
            behavior = o.optString("behavior", "classical"),
            url = o.optString("url", ""),
            path = o.optString("path", ""),
            format = o.optString("format", "yaml"),
            intervalSec = o.optInt("intervalSec", 86400)
        )
    }
}
