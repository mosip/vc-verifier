package io.mosip.vercred.vcverifier.credentialverifier

interface RevocationChecker {
    fun isRevoked(credential: String): Boolean
}
