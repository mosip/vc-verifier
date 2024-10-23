package io.mosip.vercred.vcverifier.signature.impl

import com.android.identity.internal.Util
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey

class CoseSignatureVerifierImpl: SignatureVerifier {
    override fun verify(
        publicKey: PublicKey,
        signData: ByteArray,
        signature: ByteArray?,
        provider: BouncyCastleProvider?,
    ): Boolean {
        val coseSign1 = CborDataItemUtils.fromByteArray(signData)
        val coseSign1CheckSignature =
            Util.coseSign1CheckSignature(coseSign1, byteArrayOf(), publicKey)
        if (!coseSign1CheckSignature)
            throw SignatureVerificationException("Error while doing COSE signature verification with algorithm - ${publicKey.algorithm}")
        return true
    }
}