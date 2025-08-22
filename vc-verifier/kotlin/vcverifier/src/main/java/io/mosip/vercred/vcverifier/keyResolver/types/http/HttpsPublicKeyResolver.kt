package io.mosip.vercred.vcverifier.keyResolver.types.http

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_HEX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_JWK
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_PEM
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.networkManager.HTTP_METHOD.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyResolver
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyFromHex
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyFromJWK
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyObjectFromPemPublicKey
import io.mosip.vercred.vcverifier.keyResolver.getPublicKeyObjectFromPublicKeyMultibase
import java.security.PublicKey
import java.util.logging.Logger

class HttpsPublicKeyResolver : PublicKeyResolver {

    private val logger = Logger.getLogger(HttpsPublicKeyResolver::class.java.name)

    override fun resolve(uri: String, keyId: String?): PublicKey {
        try {
            val response = sendHTTPRequest(uri, GET)

            response?.let {
                val publicKeyStr = it[PUBLIC_KEY_PEM].toString()
                val keyType = it[KEY_TYPE].toString()
                return when {
                    PUBLIC_KEY_JWK in it -> getPublicKeyFromJWK(
                        publicKeyStr, keyType
                    )
                    PUBLIC_KEY_HEX in it -> getPublicKeyFromHex(
                        publicKeyStr, keyType
                    )
                    PUBLIC_KEY_PEM in it -> getPublicKeyObjectFromPemPublicKey(
                        publicKeyStr, keyType
                    )
                    PUBLIC_KEY_MULTIBASE in it -> getPublicKeyObjectFromPublicKeyMultibase(
                        publicKeyStr, keyType
                    )

                    else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
                }
            }
            throw PublicKeyNotFoundException("Public key string not found")
        } catch (e: Exception) {
            logger.severe("Error fetching public key string $e")
            throw PublicKeyNotFoundException("Public key string not found")
        }
    }
}