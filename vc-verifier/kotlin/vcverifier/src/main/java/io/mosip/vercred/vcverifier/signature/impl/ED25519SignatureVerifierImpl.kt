package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.signature.bouncyCastleProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Signature
import java.util.logging.Logger

class ED25519SignatureVerifierImpl : SignatureVerifier {
    private val logger = Logger.getLogger(ED25519SignatureVerifierImpl::class.java.name)

    override fun verify(
        publicKey: PublicKey,
        signData: ByteArray,
        signature: ByteArray?,
        provider: BouncyCastleProvider?,
    ): Boolean {
        try {
                Signature.getInstance(CredentialVerifierConstants.ED25519_ALGORITHM, provider ?: bouncyCastleProvider )
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