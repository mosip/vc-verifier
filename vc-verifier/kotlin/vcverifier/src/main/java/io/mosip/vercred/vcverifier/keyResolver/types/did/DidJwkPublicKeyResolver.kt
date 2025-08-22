package io.mosip.vercred.vcverifier.keyResolver.types.did

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec


class DidJwkPublicKeyResolver : DidPublicKeyResolver() {
    private var provider: BouncyCastleProvider = BouncyCastleProvider()
    private var b64Decoder: Base64Decoder = Base64Decoder()

    override fun extractPublicKey(
        parsedDID: ParsedDID,
        keyId: String?
    ): PublicKey {
        try {
            val jwk: JWK = JWK.parse(
                String(
                    b64Decoder.decodeFromBase64Url(parsedDID.id)
                )
            )

            if (jwk.keyType != KeyType.OKP) {
                throw PublicKeyTypeNotSupportedException(message = "KeyType - ${jwk.keyType} is not supported. Supported: OKP")
            }

            val publicKeyBytes =
                b64Decoder.decodeFromBase64Url(jwk.toOctetKeyPair().x.toString())
            val algorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
            val subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKeyBytes)
            val encodedKey = subjectPublicKeyInfo.encoded
            val keySpec = X509EncodedKeySpec(encodedKey)
            val keyFactory = KeyFactory.getInstance(JWS_EDDSA_SIGN_ALGO_CONST, provider)
            return keyFactory.generatePublic(keySpec)
        } catch (e: Exception) {
            when (e) {
                is IllegalArgumentException -> throw PublicKeyResolutionFailedException("Invalid base64url encoding for public key data")
                is InvalidKeySpecException, is PublicKeyTypeNotSupportedException -> throw e
                else -> {
                    throw UnknownException("Error while getting public key object")
                }
            }
        }
    }
}