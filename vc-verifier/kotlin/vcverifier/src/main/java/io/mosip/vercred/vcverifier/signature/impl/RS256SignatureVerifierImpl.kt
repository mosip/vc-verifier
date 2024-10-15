package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey

class RS256SignatureVerifierImpl : SignatureVerifier {
    override fun verify(publicKey: PublicKey, signData: ByteArray, signature: ByteArray, provider: BouncyCastleProvider): Boolean {
        try {
            val rsSignature: java.security.Signature =
                java.security.Signature.getInstance(CredentialVerifierConstants.RS256_ALGORITHM)
            rsSignature.initVerify(publicKey)
            rsSignature.update(signData)
            return rsSignature.verify(signature)
        } catch (e: Exception) {
            throw SignatureVerificationException("Error while doing signature verification using RS256 algorithm")
        }
    }
}