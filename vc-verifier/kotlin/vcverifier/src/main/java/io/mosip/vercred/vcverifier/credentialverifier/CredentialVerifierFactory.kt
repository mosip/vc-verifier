package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVerifiableCredential

class CredentialVerifierFactory {
    fun get(credentialFormat: CredentialFormat): VerifiableCredential {
        return when (credentialFormat) {
            CredentialFormat.LDP_VC -> LdpVerifiableCredential()
            CredentialFormat.MSO_MDOC -> TODO()
        }
    }
}