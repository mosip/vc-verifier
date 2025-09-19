package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.signature.SignatureFactory
import java.security.PublicKey
import kotlin.text.Charsets.UTF_8

class SdJwtVerifier {

    fun verify(credential: String): Boolean {
        val parts = credential.split("~")
        val jwt = parts[0]
        return verifyJWTSignature(jwt)
    }

    private fun verifyJWTSignature(jwt: String): Boolean {
        val jwtParts = jwt.split(".")
        if (jwtParts.size != 3)
            throw IllegalArgumentException("Invalid JWT format")

        val jwsObject = JWSObject.parse(jwt)
        val header = jwsObject.header

        if (header.x509CertChain.isEmpty()) {
            throw IllegalArgumentException("No X.509 certificate chain found in JWT header")
        }

        val certBase64 = header.x509CertChain[0].toString()
        val publicKey = getPublicKeyFromCertificate(certBase64)

        val signedData = "${jwtParts[0]}.${jwtParts[1]}"
        val signatureBytes = Base64Decoder().decodeFromBase64Url(jwtParts[2])

        val signatureVerifier = SignatureFactory().get(jwsObject.header.algorithm.name)

        return try {
            signatureVerifier.verify(
                publicKey,
                signedData.toByteArray(UTF_8),
                signatureBytes
            )
        } catch (e: Exception) {
            throw SignatureVerificationException("Error while verifying signature: ${e.message}")
        }
    }

    private fun getPublicKeyFromCertificate(certBase64: String): PublicKey {
        val certificateBytes = Base64Decoder().decodeFromBase64(certBase64)
        val x509Certificate = Util.toX509Certificate(certificateBytes)
        val publicKey = x509Certificate.publicKey
        return publicKey
    }
}