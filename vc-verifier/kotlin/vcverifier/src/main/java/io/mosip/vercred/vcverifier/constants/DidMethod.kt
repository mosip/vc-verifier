package io.mosip.vercred.vcverifier.constants

enum class DidMethod(val value: String) {
    WEB("web"),
    KEY("key"),
    JWK("jwk");

    companion object {
        fun fromValue(value: String): DidMethod? =
            entries.find { it.value.equals(value, ignoreCase = false) }
    }
}