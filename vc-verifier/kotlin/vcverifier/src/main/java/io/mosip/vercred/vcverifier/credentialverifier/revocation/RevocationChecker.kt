package io.mosip.vercred.vcverifier.credentialverifier.revocation

interface RevocationChecker {
    fun isRevoked(credential: String): Boolean
}
