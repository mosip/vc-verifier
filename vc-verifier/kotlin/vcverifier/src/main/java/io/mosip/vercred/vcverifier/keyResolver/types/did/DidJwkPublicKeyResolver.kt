package io.mosip.vercred.vcverifier.keyResolver.types.did

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_KEY_TYPE
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyFromJWK
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException


class DidJwkPublicKeyResolver : DidPublicKeyResolver() {
    private var b64Decoder: Base64Decoder = Base64Decoder()

    override fun extractPublicKey(
        parsedDID: ParsedDID,
        keyId: String?
    ): PublicKey {
        try {
            val jwkJson = String(b64Decoder.decodeFromBase64Url(parsedDID.id))
            val jwk: JWK = JWK.parse(jwkJson)

            return when (jwk.keyType) {
                KeyType.OKP -> getPublicKeyFromJWK(jwkJson,ED25519_KEY_TYPE_2020)
                KeyType.EC -> getPublicKeyFromJWK(jwkJson,ES256K_KEY_TYPE_2019)
                KeyType.RSA -> getPublicKeyFromJWK(jwkJson,RSA_KEY_TYPE)
                else -> throw PublicKeyTypeNotSupportedException(
                    "KeyType - ${jwk.keyType} is not supported. Supported: OKP, EC, RSA"
                )
            }

        } catch (e: Exception) {
            when (e) {
                is IllegalArgumentException -> throw PublicKeyResolutionFailedException("Invalid base64url encoding for public key data")
                is InvalidKeySpecException,
                is PublicKeyTypeNotSupportedException -> throw e
                else -> throw UnknownException("Error while getting public key object")
            }
        }
    }
}