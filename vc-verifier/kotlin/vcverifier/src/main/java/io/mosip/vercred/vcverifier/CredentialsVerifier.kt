package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialFormat.LDP_VC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.EXCEPTION_DURING_VERIFICATION
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_MESSAGE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.credentialverifier.verifier.LdpVerifier
import io.mosip.vercred.vcverifier.data.VerificationResult
import org.slf4j.Logger
import org.slf4j.LoggerFactory


class CredentialsVerifier {
    private val Logger: Logger = LoggerFactory.getLogger(CredentialsVerifier::class.java.name)


    /**
     * @deprecated This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification
     * Please use verify(credentials: String, format: CredentialFormat) instead, which is designed for supporting different VC formats.
     * This method only supports LDP VC format
     */
    @Deprecated("This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification")
    fun verifyCredentials(credentials: String?): Boolean {
        if(credentials==null){
            Logger.error("Error - Input credential is null")
            throw RuntimeException("Input credential is null")
        }
        val credentialVerifier = CredentialVerifierFactory().get(LDP_VC)
        return credentialVerifier.verify(credentials)
    }

    fun verify(credential: String, credentialFormat: CredentialFormat): VerificationResult {
        val credentialVerifier = CredentialVerifierFactory().get(credentialFormat)
        val validationStatus = credentialVerifier.validate(credential)
        if (validationStatus.validationMessage.isNotEmpty() && !validationStatus.validationErrorCode.contentEquals(ERROR_CODE_VC_EXPIRED)) {
            return VerificationResult(false, validationStatus.validationMessage, validationStatus.validationErrorCode)
        }
        return try {
            val verifySignatureStatus = credentialVerifier.verify(credential)
            if (!verifySignatureStatus) {
                return  VerificationResult(false, ERROR_MESSAGE_VERIFICATION_FAILED, ERROR_CODE_VERIFICATION_FAILED)
            }
            VerificationResult(true, validationStatus.validationMessage, validationStatus.validationErrorCode)
        } catch (e: Exception) {
            VerificationResult(false, "$EXCEPTION_DURING_VERIFICATION${e.message}", validationStatus.validationErrorCode)
        }
    }
}