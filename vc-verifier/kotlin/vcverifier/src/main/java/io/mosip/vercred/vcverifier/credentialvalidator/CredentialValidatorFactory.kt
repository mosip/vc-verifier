package io.mosip.vercred.vcverifier.credentialvalidator

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialvalidator.types.LdpVcCredentialValidator
import io.mosip.vercred.vcverifier.data.VerificationResult

class CredentialValidatorFactory {
    fun validate(credential: String, credentialFormat: CredentialFormat): VerificationResult {
        return when (credentialFormat) {
            CredentialFormat.LDP_VC -> LdpVcCredentialValidator().validate(
                credential = credential
            )
        }
    }
}
