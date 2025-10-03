package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.toPublicKey
import io.mosip.vercred.vcverifier.utils.Base64Decoder
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

            return toPublicKey(jwkJson)
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

