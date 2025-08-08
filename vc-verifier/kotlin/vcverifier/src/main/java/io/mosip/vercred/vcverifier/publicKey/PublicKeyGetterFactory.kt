package io.mosip.vercred.vcverifier.publicKey

import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.publicKey.impl.DidJwkPublicKeyGetter
import io.mosip.vercred.vcverifier.publicKey.impl.DidKeyPublicKeyGetter
import io.mosip.vercred.vcverifier.publicKey.impl.DidWebPublicKeyGetter
import io.mosip.vercred.vcverifier.publicKey.impl.HttpsPublicKeyGetter
import java.net.URI
import java.security.PublicKey


class PublicKeyGetterFactory {

    fun get(verificationMethod: URI): PublicKey {
        val verificationMethodStr = verificationMethod.toString()
        return when {
            verificationMethodStr.startsWith("did:web") -> DidWebPublicKeyGetter().get(verificationMethod)
            verificationMethodStr.startsWith("did:key") -> DidKeyPublicKeyGetter().get(verificationMethod)
            verificationMethodStr.startsWith("did:jwk") -> DidJwkPublicKeyGetter().get(verificationMethod)
            verificationMethodStr.startsWith("http") -> HttpsPublicKeyGetter().get(verificationMethod)
            else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
        }
    }
}