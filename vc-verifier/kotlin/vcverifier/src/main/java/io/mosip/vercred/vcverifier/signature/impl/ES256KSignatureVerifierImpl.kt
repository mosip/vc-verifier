package io.mosip.vercred.vcverifier.signature.impl

import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.io.ByteArrayOutputStream
import java.math.BigInteger

class ES256KSignatureVerifierImpl : SignatureVerifier {
    override fun verify(publicKey: PublicKey, signData: ByteArray, signature: ByteArray?, provider: BouncyCastleProvider?): Boolean {
        if (signature == null || signature.size != 64) {
            throw SignatureVerificationException("Invalid signature length: Expected 64 bytes for R || S format")
        }

        try {
            val derSignature = convertRawSignatureToDER(signature) // Convert to ASN.1 DER

            Signature.getInstance(CredentialVerifierConstants.EC_ALGORITHM, provider)
                .apply {
                    initVerify(publicKey)
                    update(signData)
                    return verify(derSignature)
                }
        } catch (e: Exception) {
            throw SignatureVerificationException("Error while doing signature verification using ES256K algorithm: ${e.message}")
        }
    }

    /**
     * Converts a raw ECDSA (R || S) signature (64 bytes) into ASN.1 DER format.
     *
     * Java's `Signature.verify()` expects the signature in ASN.1 DER format, but many cryptographic
     * libraries return signatures in raw (R || S) format. This function ensures compatibility by
     * wrapping `R` and `S` into an ASN.1 DER sequence.
     *
     * ASN.1 DER Format:
     *  - 0x30 (Sequence)
     *  - Total length
     *  - 0x02 (Integer marker) + Length of R + R value
     *  - 0x02 (Integer marker) + Length of S + S value
     *
     * @param signature Raw ECDSA signature (64 bytes: [R (32 bytes)] [S (32 bytes)])
     * @return DER-encoded signature for Java `Signature.verify()`
     * @throws IllegalArgumentException if the signature length is incorrect
     */
    private fun convertRawSignatureToDER(signature: ByteArray): ByteArray {
        val r = BigInteger(1, signature.copyOfRange(0, 32))
        val s = BigInteger(1, signature.copyOfRange(32, 64))

        val outputStream = ByteArrayOutputStream()
        val derEncoder = java.io.DataOutputStream(outputStream)

        derEncoder.writeByte(0x30)
        val seqBytes = ByteArrayOutputStream()

        seqBytes.write(0x02)
        seqBytes.write(r.toByteArray().size)
        seqBytes.write(r.toByteArray())

        seqBytes.write(0x02)
        seqBytes.write(s.toByteArray().size)
        seqBytes.write(s.toByteArray())

        val derSeq = seqBytes.toByteArray()
        derEncoder.write(derSeq.size)
        derEncoder.write(derSeq)

        return outputStream.toByteArray()
    }
}
