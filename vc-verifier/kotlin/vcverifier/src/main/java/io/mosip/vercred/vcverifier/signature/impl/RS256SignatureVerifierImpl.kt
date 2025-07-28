package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Signature

private var provider: BouncyCastleProvider = BouncyCastleProvider()

class RS256SignatureVerifierImpl : SignatureVerifier {
    override fun verify(
        publicKey: PublicKey,
        signData: ByteArray,
        signature: ByteArray?,
    ): Boolean {
        try {
            Signature.getInstance(CredentialVerifierConstants.RS256_ALGORITHM, provider)
                .apply {
                    initVerify(publicKey)
                    update(signData)
                    return verify(signature)
                }
        } catch (e: Exception) {
            throw SignatureVerificationException("Error while doing signature verification using RS256 algorithm")
        }
    }
}