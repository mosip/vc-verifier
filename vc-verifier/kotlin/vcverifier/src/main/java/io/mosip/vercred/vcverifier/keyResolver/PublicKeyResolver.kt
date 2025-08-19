package io.mosip.vercred.vcverifier.keyResolver

import java.security.PublicKey

interface PublicKeyResolver {
    fun resolve(uri: String, keyId: String? = null): PublicKey
}