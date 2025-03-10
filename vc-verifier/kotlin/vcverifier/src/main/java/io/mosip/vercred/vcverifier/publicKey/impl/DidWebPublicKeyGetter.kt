package io.mosip.vercred.vcverifier.publicKey.impl

import com.fasterxml.jackson.databind.ObjectMapper
import io.mosip.vercred.vcverifier.DidWebResolver
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_HEX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_JWK
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFICATION_METHOD
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.publicKey.*
import java.net.URI
import java.security.PublicKey
import java.util.logging.Logger

class DidWebPublicKeyGetter : PublicKeyGetter {

    private val logger = Logger.getLogger(DidWebPublicKeyGetter::class.java.name)

    override fun get(verificationMethod: URI): PublicKey {
        try {
            val didDocument = DidWebResolver(verificationMethod.toString()).resolve()

            val verificationMethods = didDocument[VERIFICATION_METHOD] as? List<Map<String, Any>>
                ?: throw PublicKeyNotFoundException("Verification method not found in DID document")

            val method = verificationMethods.firstOrNull()
                ?: throw PublicKeyNotFoundException("No verification methods available in DID document")

            val publicKeyStr = getKeyValue(method, arrayOf(PUBLIC_KEY_MULTIBASE, PUBLIC_KEY_JWK,
                PUBLIC_KEY_HEX
            ))
            val keyType = getKeyValue(method, arrayOf(KEY_TYPE))
            return when {
                isPublicKeyJwk(publicKeyStr) -> getPublicKeyFromJWK(publicKeyStr)
                isPublicKeyHex(publicKeyStr) -> getPublicKeyFromHex(publicKeyStr)
                isPemPublicKey(publicKeyStr) -> getPublicKeyObjectFromPemPublicKey(publicKeyStr, keyType)
                isPublicKeyMultibase(publicKeyStr) -> getPublicKeyObjectFromPublicKeyMultibase(publicKeyStr, keyType)
                else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
            }
        } catch (e: Exception) {
            logger.severe("Error fetching public key: ${e.message}")
            throw PublicKeyNotFoundException(e.message ?: "Unknown error")
        }
    }

    /**
     * Extracts the first available value for a given list of keys.
     */
    private fun getKeyValue(responseObjectNode: Map<String, Any>, keys: Array<String>): String {
        for (key in keys) {
            responseObjectNode[key]?.let { value ->
                return when (value) {
                    is String -> value
                    else -> ObjectMapper().writeValueAsString(value)
                }
            }
        }

        throw PublicKeyNotFoundException("None of the provided keys were found in verification method")
    }
}
