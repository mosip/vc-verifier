package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.data.Result
import io.mosip.vercred.vcverifier.exception.StatusCheckException

interface VerifiableCredential {
    fun validate(credential: String): ValidationStatus
    fun verify(credential: String): Boolean
    fun checkStatus(credential: String, statusPurposes: List<String>?): Map<String, Result<StatusCheckException>> {
        throw UnsupportedOperationException("Credential status checking not supported for this credential format")
    }
}