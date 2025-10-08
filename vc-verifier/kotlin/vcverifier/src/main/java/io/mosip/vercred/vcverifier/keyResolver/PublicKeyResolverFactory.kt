package io.mosip.vercred.vcverifier.keyResolver

import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import io.mosip.vercred.vcverifier.keyResolver.types.http.HttpsPublicKeyResolver
import java.net.URI
import java.security.PublicKey


internal const val DID_PREFIX = "did:"
private const val HTTP_PREFIX = "http"

class PublicKeyResolverFactory {

    fun get(verificationMethod: URI): PublicKey {
        val verificationMethodStr = verificationMethod.toString()
        return when {
            verificationMethodStr.startsWith(DID_PREFIX) -> DidPublicKeyResolver().resolve(verificationMethod.toString())
            verificationMethodStr.startsWith(HTTP_PREFIX) -> HttpsPublicKeyResolver().resolve(verificationMethod.toString())
            else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
        }
    }
}