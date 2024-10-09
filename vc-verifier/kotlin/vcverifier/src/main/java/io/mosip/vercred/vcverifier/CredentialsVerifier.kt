package io.mosip.vercred.vcverifier

import android.util.Log
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory


class CredentialsVerifier {
    private val tag: String = CredentialsVerifier::class.java.name

    /**
     * @deprecated This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification
     * Please use verify(credentials: String, format: CredentialFormat) instead, which is designed for supporting different VC formats.
     */
    @Deprecated("This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification")
    fun verifyCredentials(credentials: String?): Boolean {
        if(credentials==null){
            Log.e(tag, "Error - Input credential is null")
            throw RuntimeException("Input credential is null")
        }
        return CredentialVerifierFactory().verify(credentials,CredentialFormat.LDP_VC)
    }


    fun verify(credential: String, credentialFormat: CredentialFormat): Boolean {
        return CredentialVerifierFactory().verify(credential,credentialFormat)
    }
}