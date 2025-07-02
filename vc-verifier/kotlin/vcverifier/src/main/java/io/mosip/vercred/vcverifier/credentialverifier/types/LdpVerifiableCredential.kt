package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.revocation.LdpRevokeChecker
import io.mosip.vercred.vcverifier.credentialverifier.validator.LdpValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.LdpVerifier
import io.mosip.vercred.vcverifier.data.ValidationStatus

class LdpVerifiableCredential : VerifiableCredential {
    override fun validate(credential: String): ValidationStatus {
        return LdpValidator().validate(credential)
    }

    override fun verify(credential: String): Boolean {
        return LdpVerifier().verify(credential)
    }

    override fun isRevoked(credential: String): Boolean {
        return LdpRevokeChecker().isRevoked(credential)
    }


}