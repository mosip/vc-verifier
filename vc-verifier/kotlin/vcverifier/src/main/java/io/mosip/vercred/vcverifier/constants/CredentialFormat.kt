package io.mosip.vercred.vcverifier.constants

enum class CredentialFormat(val value: String) {
    LDP_VC("ldp_vc"),
    SD_JWT("sd_jwt"),
    MSO_MDOC("mso_mdoc");

    companion object {
        fun fromValue(value: String): CredentialFormat? {
            return entries.find { it.value == value }
        }
    }
}
