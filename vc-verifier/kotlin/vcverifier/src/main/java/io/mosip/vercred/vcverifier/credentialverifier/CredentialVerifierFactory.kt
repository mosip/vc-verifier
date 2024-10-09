package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVcCredentialVerifier

class CredentialVerifierFactory {
    fun verify(credential: String, credentialFormat: CredentialFormat): Boolean {
        return when (credentialFormat) {
            CredentialFormat.LDP_VC -> LdpVcCredentialVerifier().verify(
                credential = credential
            )
        }
    }
}
