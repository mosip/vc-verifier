package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.EXCEPTION_DURING_VERIFICATION
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.credentialvalidator.CredentialValidatorFactory
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.data.VerificationResult


class CredentialsVerifier {
    private val tag: String = CredentialsVerifier::class.java.name

    /**
     * @deprecated This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification
     * Please use verify(credentials: String, format: CredentialFormat) instead, which is designed for supporting different VC formats.
     */
    @Deprecated("This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification")
    fun verifyCredentials(credentials: String?): VerificationResult {
        val verificationResult = CredentialValidatorFactory().validate(credential = credentials.orEmpty(), CredentialFormat.LDP_VC)

        //Return Validation Error
        if (!verificationResult.verificationStatus) {
            return verificationResult
        }

        return try {
            val verifySignatureStatus = CredentialVerifierFactory().verify(credentials.orEmpty(), CredentialFormat.LDP_VC)
            verificationResult.verificationStatus = verifySignatureStatus
            if (!verifySignatureStatus) {
                verificationResult.verificationErrorMessage = VERIFICATION_FAILED
            }
            verificationResult
        } catch (e: Exception) {
            VerificationResult(false, "$EXCEPTION_DURING_VERIFICATION${e.message}")
        }
    }


    fun verify(credential: String, credentialFormat: CredentialFormat): VerificationResult {
        val verificationResult = CredentialValidatorFactory().validate(credential = credential, CredentialFormat.LDP_VC)

        //Return Validation Error
        if (!verificationResult.verificationStatus) {
            return verificationResult
        }

        return try {
            val verifySignatureStatus = CredentialVerifierFactory().verify(credential, credentialFormat)
            verificationResult.verificationStatus = verifySignatureStatus
            if (!verifySignatureStatus) {
                verificationResult.verificationErrorMessage = VERIFICATION_FAILED
            }
            verificationResult
        } catch (e: Exception) {
            VerificationResult(false, "$EXCEPTION_DURING_VERIFICATION${e.message}")
        }

    }
}