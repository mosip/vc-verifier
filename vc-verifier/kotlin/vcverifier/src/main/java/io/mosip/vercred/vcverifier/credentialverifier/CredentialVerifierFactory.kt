package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVcCredentialVerifier

class CredentialVerifierFactory {
    fun verify(credentials: String, credentialFormat: CredentialFormat): Boolean {
        if (credentialFormat == CredentialFormat.LDP_VC) {
            return LdpVcCredentialVerifier().verify(credentials)
        }
        return false
    }
}
