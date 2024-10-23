package io.mosip.vercred.vcverifier.credentialverifier


interface VerifiableCredential {
    fun validate(credential: String): String
    fun verify(credential: String): Boolean
}