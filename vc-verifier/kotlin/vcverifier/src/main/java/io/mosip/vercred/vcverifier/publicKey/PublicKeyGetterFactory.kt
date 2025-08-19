package io.mosip.vercred.vcverifier.publicKey

import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.publicKey.impl.HttpsPublicKeyResolver
import io.mosip.vercred.vcverifier.publicKey.types.did.DidPublicKeyResolver
import java.net.URI
import java.security.PublicKey


private const val DID_PREFIX = "did:"
private const val HTTP_PREFIX = "http"

class PublicKeyGetterFactory {

    fun get(verificationMethod: URI): PublicKey {
        val verificationMethodStr = verificationMethod.toString()
        return when {
            verificationMethodStr.startsWith(DID_PREFIX) -> DidPublicKeyResolver().resolve(verificationMethod.toString())
            verificationMethodStr.startsWith(HTTP_PREFIX) -> HttpsPublicKeyResolver().resolve(verificationMethod.toString())
            else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
        }
    }
}