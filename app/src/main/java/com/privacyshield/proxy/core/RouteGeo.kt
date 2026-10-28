package com.privacyshield.proxy.core

/**
 * Geographic identity handed to Blackbox with every route assignment.
 * [locale] is chosen from the exit country so the guest is not left on the phone locale.
 */
data class RouteGeo(
    val countryIso: String = "",
    val city: String = "",
    val region: String = "",
    val latitude: Double? = null,
    val longitude: Double? = null,
    val timezoneId: String = "",
    val locale: String = ""
) {
    fun withCountryFallback(hint: String): RouteGeo {
        if (countryIso.isNotBlank()) return this
        if (hint.isBlank()) return this
        return copy(countryIso = hint, locale = locale.ifBlank { RouteLocale.forCountry(hint) })
    }

    companion object {
        fun fromTest(result: ProxyTester.Result, countryHint: String = ""): RouteGeo {
            val country = result.countryIso.ifBlank { countryHint }
            return RouteGeo(
                countryIso = country,
                city = result.city,
                region = result.region,
                latitude = result.latitude,
                longitude = result.longitude,
                timezoneId = result.timezoneId,
                locale = if (country.isBlank()) "" else RouteLocale.forCountry(country)
            )
        }
    }
}

object RouteLocale {
    /** BCP 47 tag whose region matches the exit country. Language is the usual primary language. */
    fun forCountry(iso: String): String {
        val cc = iso.trim().lowercase().let { if (it == "uk") "gb" else it }
        if (!cc.matches(Regex("[a-z]{2}"))) return ""
        val language = when (cc) {
            "de", "at", "ch" -> "de"
            "fr", "be" -> "fr"
            "es", "mx", "ar", "co", "cl" -> "es"
            "br" -> "pt"
            "pt" -> "pt"
            "it" -> "it"
            "nl" -> "nl"
            "pl" -> "pl"
            "tr" -> "tr"
            "ru" -> "ru"
            "jp" -> "ja"
            "kr" -> "ko"
            "cn", "tw", "hk" -> "zh"
            "sa", "ae", "eg" -> "ar"
            "id" -> "id"
            "th" -> "th"
            "vn" -> "vi"
            "se" -> "sv"
            "no" -> "nb"
            "dk" -> "da"
            "fi" -> "fi"
            else -> "en"
        }
        return "$language-${cc.uppercase()}"
    }
}
