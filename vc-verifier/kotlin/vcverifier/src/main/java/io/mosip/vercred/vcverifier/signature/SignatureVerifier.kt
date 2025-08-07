package io.mosip.vercred.vcverifier.signature

import java.security.PublicKey

interface SignatureVerifier {
    fun verify(publicKey: PublicKey, signData: ByteArray, signature: ByteArray?): Boolean
}