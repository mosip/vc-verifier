package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.statusChecker.LdpStatusChecker
import io.mosip.vercred.vcverifier.credentialverifier.validator.LdpValidator
import io.mosip.vercred.vcverifier.credentialverifier.verifier.LdpVerifier
import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import io.mosip.vercred.vcverifier.data.Result

class LdpVerifiableCredential : VerifiableCredential {
    override fun validate(credential: String): ValidationStatus {
        return LdpValidator().validate(credential)
    }

    override fun verify(credential: String): Boolean {
        return LdpVerifier().verify(credential)
    }

    override fun checkStatus(credential: String, statusPurposes: List<String>?): Map<String, Result<StatusCheckException>> {
        return LdpStatusChecker().getStatuses(credential, statusPurposes)
    }
}