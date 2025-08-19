package io.mosip.vercred.vcverifier.publicKey

import java.security.PublicKey

interface PublicKeyResolver {
    fun resolve(uri: String, keyId: String? = null): PublicKey
}