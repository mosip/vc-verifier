package io.mosip.vercred.vcverifier

import android.util.Log
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVcCredentialVerifier
import io.mosip.vercred.vcverifier.utils.Util


class CredentialsVerifier {
    private val tag: String = CredentialsVerifier::class.java.name

    fun verifyCredentials(credentials: String?): Boolean {
        if(credentials==null){
            Log.e(tag, "Error - Input credential is null")
            throw RuntimeException("Input credential is null")
        }
        return CredentialVerifierFactory().verify(credentials,CredentialFormat.LDP_VC)
    }
}