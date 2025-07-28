package io.mosip.vercred.vcverifier.credentialverifier.types

import io.mosip.vercred.vcverifier.credentialverifier.VerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.verifier.SdJwtVerifier
import io.mosip.vercred.vcverifier.data.ValidationStatus

class SdJwtVerifiableCredential: VerifiableCredential {
    override fun validate(credential: String): ValidationStatus {
        //TODO("Not yet implemented")
        return ValidationStatus(
            validationMessage = "",
            validationErrorCode = ""
        )
    }

    override fun verify(credential: String): Boolean {
        return SdJwtVerifier().verify(credential)
    }

    override fun isRevoked(credential: String): Boolean {
        //TODO("Not yet implemented")
        return false;
    }
}