package io.mosip.vercred.vcverifier.publicKey

import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.publicKey.types.did.types.DidJwkPublicKeyResolver
import io.mosip.vercred.vcverifier.publicKey.impl.DidKeyPublicKeyResolver
import io.mosip.vercred.vcverifier.publicKey.impl.DidWebPublicKeyResolver
import io.mosip.vercred.vcverifier.publicKey.impl.HttpsPublicKeyResolver
import java.net.URI
import java.security.PublicKey


class PublicKeyGetterFactory {

    fun get(verificationMethod: URI): PublicKey {
        val verificationMethodStr = verificationMethod.toString()
        return when {
            verificationMethodStr.startsWith("did:web") -> DidWebPublicKeyResolver().resolve(verificationMethod)
            verificationMethodStr.startsWith("did:key") -> DidKeyPublicKeyResolver().resolve(verificationMethod)
            verificationMethodStr.startsWith("did:jwk") -> DidJwkPublicKeyResolver().resolve(verificationMethod)
            verificationMethodStr.startsWith("http") -> HttpsPublicKeyResolver().resolve(verificationMethod)
            else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
        }
    }
}