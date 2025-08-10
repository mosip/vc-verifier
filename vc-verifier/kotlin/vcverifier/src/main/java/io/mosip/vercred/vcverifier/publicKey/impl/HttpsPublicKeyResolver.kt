package io.mosip.vercred.vcverifier.publicKey.impl

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_HEX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_JWK
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_PEM
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.networkManager.HTTP_METHOD.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.publicKey.PublicKeyResolver
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyFromHex
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyFromJWK
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPemPublicKey
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPublicKeyMultibase
import java.net.URI
import java.security.PublicKey
import java.util.logging.Logger

class HttpsPublicKeyResolver : PublicKeyResolver {

    private val logger = Logger.getLogger(HttpsPublicKeyResolver::class.java.name)

    override fun resolve(verificationMethod: URI): PublicKey {
        try {
            val response = sendHTTPRequest(verificationMethod.toString(), GET)

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