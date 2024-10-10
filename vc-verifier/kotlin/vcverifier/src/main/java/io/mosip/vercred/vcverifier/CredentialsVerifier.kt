package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory


class CredentialsVerifier {
    private val tag: String = CredentialsVerifier::class.java.name

    /**
     * @deprecated This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification
     * Please use verify(credentials: String, format: CredentialFormat) instead, which is designed for supporting different VC formats.
     */
    @Deprecated("This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification")
    fun verifyCredentials(credentials: String?): VerificationResult {
        val verificationResult = CredentialsValidator().validateCredential(vcJsonString = credentials)
        return if (verificationResult.verificationStatus) {
            VerificationResult(CredentialVerifierFactory().verify(credentials.orEmpty(), CredentialFormat.LDP_VC))
        } else {
            verificationResult
        }
    }


    fun verify(credential: String, credentialFormat: CredentialFormat): VerificationResult {
        val verificationResult = CredentialsValidator().validateCredential(vcJsonString = credential)
        return if (verificationResult.verificationStatus) {
            return VerificationResult(CredentialVerifierFactory().verify(credential,credentialFormat))
        } else {
            verificationResult
        }

    }
}