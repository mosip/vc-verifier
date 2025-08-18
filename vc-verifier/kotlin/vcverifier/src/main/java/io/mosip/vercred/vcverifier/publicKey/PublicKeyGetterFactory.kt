package io.mosip.vercred.vcverifier.publicKey

import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.publicKey.impl.HttpsPublicKeyResolver
import io.mosip.vercred.vcverifier.publicKey.types.did.DidPublicKeyResolver
import java.net.URI
import java.security.PublicKey


class PublicKeyGetterFactory {

    fun get(verificationMethod: URI): PublicKey {
        val verificationMethodStr = verificationMethod.toString()
        return when {
            verificationMethodStr.startsWith("did:") -> DidPublicKeyResolver().resolve(verificationMethod)
            verificationMethodStr.startsWith("http") -> HttpsPublicKeyResolver().resolve(verificationMethod)
            else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
        }
    }
}