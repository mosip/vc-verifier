package io.mosip.vercred.vcverifier.publicKey.impl

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_PEM
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.networkManager.HTTP_METHOD.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetter
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPemPublicKey
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPublicKeyMultibase
import io.mosip.vercred.vcverifier.publicKey.isPemPublicKey
import io.mosip.vercred.vcverifier.publicKey.isPublicKeyMultibase
import java.net.URI
import java.security.PublicKey
import java.util.logging.Logger

class HttpsPublicKeyGetter : PublicKeyGetter {

    private val logger = Logger.getLogger(HttpsPublicKeyGetter::class.java.name)

    override fun get(verificationMethod: URI): PublicKey {
        try {
            val response = sendHTTPRequest(verificationMethod.toString(), GET)

            response?.let { it ->
                val publicKeyStr = it[PUBLIC_KEY_PEM].toString()
                val keyType = it[KEY_TYPE].toString()
                return when {
                    isPemPublicKey(publicKeyStr) -> getPublicKeyObjectFromPemPublicKey(publicKeyStr, keyType)
                    isPublicKeyMultibase(publicKeyStr) -> getPublicKeyObjectFromPublicKeyMultibase(publicKeyStr, keyType)
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