package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.data.VerificationResult

interface VerifiableCredential {
    fun validate(credential: String): VerificationResult
    fun verify(credential: String): Boolean
}