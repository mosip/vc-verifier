package io.mosip.vercred.vcverifier

import android.util.Log
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialFormat.LDP_VC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.EXCEPTION_DURING_VERIFICATION
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.data.VerificationResult


class CredentialVerifier {
    private val tag: String = CredentialVerifier::class.java.name

    /**
     * @deprecated This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification
     * Please use verify(credentials: String, format: CredentialFormat) instead, which is designed for supporting different VC formats.
     * This method only supports LDP VC format
     */
    @Deprecated("This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification")
    fun verifyCredentials(credentials: String?): Boolean {
        if(credentials==null){
            Log.e(tag, "Error - Input credential is null")
            throw RuntimeException("Input credential is null")
        }
        val credentialVerifier = CredentialVerifierFactory().get(LDP_VC)
        return credentialVerifier.verify(credentials)
    }


    fun verify(credential: String, credentialFormat: CredentialFormat): VerificationResult {
        val credentialVerifier = CredentialVerifierFactory().get(credentialFormat)
        val validationErrorMessage = credentialVerifier.validate(credential)
        if (validationErrorMessage.isNotEmpty() && !validationErrorMessage.contentEquals(ERROR_VC_EXPIRED)) {
            return VerificationResult(false, validationErrorMessage)
        }
        return try {
            val verifySignatureStatus = credentialVerifier.verify(credential)
            if (!verifySignatureStatus) {
                return  VerificationResult(false, VERIFICATION_FAILED)
            }
            VerificationResult(true, validationErrorMessage)
        } catch (e: Exception) {
            VerificationResult(false, "$EXCEPTION_DURING_VERIFICATION${e.message}")
        }

    }
}