package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.validator.LdpValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.LdpVerifier
import io.mosip.vercred.vcverifier.data.VerificationResult

class LdpVerifiableCredential : VerifiableCredential {
    override fun validate(credential: String): VerificationResult {
        return LdpValidator().validate(credential)
    }

    override fun verify(credential: String): Boolean {
        return LdpVerifier().verify(credential)
    }


}