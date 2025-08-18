package io.mosip.vercred.vcverifier.publicKey

import java.net.URI
import java.security.PublicKey

interface PublicKeyResolver {
    fun resolve(verificationMethod: URI, keyId: String? = null): PublicKey
}