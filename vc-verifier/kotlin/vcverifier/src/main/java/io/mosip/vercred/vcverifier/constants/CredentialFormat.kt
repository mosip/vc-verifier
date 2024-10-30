package io.mosip.vercred.vcverifier.constants

enum class CredentialFormat(val value: String) {
    LDP_VC("ldp_vc"),
    MSO_MDOC("mso_mdoc");

    companion object {
        fun fromValue(value: String): CredentialFormat? {
            return values().find { it.value == value }
        }
    }
}
