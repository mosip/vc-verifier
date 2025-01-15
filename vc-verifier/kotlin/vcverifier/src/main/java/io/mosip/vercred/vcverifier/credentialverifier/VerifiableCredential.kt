package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.response.ValidationStatus


interface VerifiableCredential {
    fun validate(credential: String): ValidationStatus
    fun verify(credential: String): Boolean
}