package io.mosip.vercred.signature

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey

interface SignatureVerifier {
    fun verify(publicKey: PublicKey, signData: ByteArray, signature: ByteArray, provider: BouncyCastleProvider): Boolean
}