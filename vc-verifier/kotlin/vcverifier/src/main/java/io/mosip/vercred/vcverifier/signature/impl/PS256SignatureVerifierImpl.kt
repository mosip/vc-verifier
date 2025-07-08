package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class PS256SignatureVerifierImpl : SignatureVerifier {

    override fun verify(
        publicKey: PublicKey,
        signData: ByteArray,
        signature: ByteArray?,
    ): Boolean {
        try {
            val psSignature: Signature =
                Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM)

            val pssParamSpec = PSSParameterSpec(
                CredentialVerifierConstants.PSS_PARAM_SHA_256,
                CredentialVerifierConstants.PSS_PARAM_MGF1,
                MGF1ParameterSpec.SHA256,
                CredentialVerifierConstants.PSS_PARAM_SALT_LEN,
                CredentialVerifierConstants.PSS_PARAM_TF
            )
            psSignature.apply {
                setParameter(pssParamSpec)
                initVerify(publicKey)
                update(signData)
                return verify(signature)
            }
        } catch (e: Exception) {
            throw SignatureVerificationException("Error while doing signature verification using PS256 algorithm")
        }
    }

}