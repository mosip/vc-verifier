package io.mosip.vercred.vcverifier.publicKey

import java.net.URI
import java.security.PublicKey

interface PublicKeyGetter {
    fun get(verificationMethod: URI): PublicKey
}