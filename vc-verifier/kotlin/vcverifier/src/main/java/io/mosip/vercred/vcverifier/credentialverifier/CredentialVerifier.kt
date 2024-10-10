package io.mosip.vercred.vcverifier.credentialverifier

interface CredentialVerifier {
    fun verify(credential: String): Boolean
}
