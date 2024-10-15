package io.mosip.vercred.vcverifier.signature.impl

import android.annotation.TargetApi
import android.os.Build
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Signature

class ED25519SignatureVerifierImpl : SignatureVerifier {


    @TargetApi(Build.VERSION_CODES.TIRAMISU)
    override fun verify(publicKey: PublicKey, signData: ByteArray, signature: ByteArray, provider: BouncyCastleProvider): Boolean {
        try {
            val ed25519Signature =
                Signature.getInstance(CredentialVerifierConstants.ED25519_ALGORITHM, provider)
                    /*.apply {
                    initVerify(publicKey)
                    update(signData)
                    verify(signature)
                }*/
            ed25519Signature.initVerify(publicKey)
            ed25519Signature.update(signData)
            return ed25519Signature.verify(signature)
        } catch (e: Exception) {
            throw SignatureVerificationException("Error while doing signature verification using ED25519 algorithm")
        }
    }
}