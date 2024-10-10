package io.mosip.vercred.vcverifier.credentialvalidator

import io.mosip.vercred.vcverifier.data.VerificationResult


interface CredentialValidator {
    fun validate(credential: String): VerificationResult
}
