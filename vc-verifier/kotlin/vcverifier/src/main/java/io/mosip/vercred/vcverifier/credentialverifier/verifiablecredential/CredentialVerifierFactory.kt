package io.mosip.vercred.vcverifier.credentialverifier.verifiablecredential

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.verifiablecredential.types.LdpVerifiableCredential

class CredentialVerifierFactory {
    fun get(credentialFormat: CredentialFormat): LdpVerifiableCredential {
        return when (credentialFormat) {
            CredentialFormat.LDP_VC -> LdpVerifiableCredential()
        }
    }
}