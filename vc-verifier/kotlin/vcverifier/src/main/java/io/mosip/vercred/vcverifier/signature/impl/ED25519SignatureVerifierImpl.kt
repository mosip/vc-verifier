package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.PresentationVerifier
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Signature
import java.util.logging.Logger

private var provider: BouncyCastleProvider = BouncyCastleProvider()

class ED25519SignatureVerifierImpl : SignatureVerifier {
    private val logger = Logger.getLogger(PresentationVerifier::class.java.name)

    override fun verify(
        publicKey: PublicKey,
        signData: ByteArray,
        signature: ByteArray?,
    ): Boolean {
        try {
            Signature.getInstance(CredentialVerifierConstants.ED25519_ALGORITHM, provider)
                .apply {
                    initVerify(publicKey)
                    update(signData)
                    return verify(signature)
                }

        } catch (e: Exception) {
            logger.severe("Error while doing signature verification using ED25519 algorithm: ${e.message}")
            throw SignatureVerificationException("Error while doing signature verification using ED25519 algorithm")
        }
    }
}