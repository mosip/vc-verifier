package io.mosip.vercred.vcverifier.publicKey.impl

import com.fasterxml.jackson.databind.ObjectMapper
import io.mosip.vercred.vcverifier.DidWebResolver
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_HEX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_JWK
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_PEM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFICATION_METHOD
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetter
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyFromHex
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyFromJWK
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPemPublicKey
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPublicKeyMultibase
import java.net.URI
import java.security.PublicKey
import java.util.logging.Logger

class DidWebPublicKeyGetter : PublicKeyGetter {

    private val logger = Logger.getLogger(DidWebPublicKeyGetter::class.java.name)

    override fun get(verificationMethodUri: URI): PublicKey {
        try {
            val didDocument = DidWebResolver(verificationMethodUri.toString()).resolve()

            val verificationMethods = didDocument[VERIFICATION_METHOD] as? List<Map<String, Any>>
                ?: throw PublicKeyNotFoundException("Verification method not found in DID document")

            val verificationMethod = verificationMethods.find { it["id"] == verificationMethodUri.toString() }
                ?: throw PublicKeyNotFoundException("No verification methods available in DID document")

            val publicKeyStr = getKeyValue(
                verificationMethod, arrayOf(
                   PUBLIC_KEY_PEM, PUBLIC_KEY_MULTIBASE, PUBLIC_KEY_JWK, PUBLIC_KEY_HEX
                )
            )
            val keyType = getKeyValue(verificationMethod, arrayOf(KEY_TYPE))
            return when {
                PUBLIC_KEY_JWK in verificationMethod -> getPublicKeyFromJWK(
                    publicKeyStr, keyType
                )
                PUBLIC_KEY_HEX in verificationMethod -> getPublicKeyFromHex(
                    publicKeyStr, keyType
                )
                PUBLIC_KEY_PEM in verificationMethod -> getPublicKeyObjectFromPemPublicKey(
                    publicKeyStr, keyType
                )
                PUBLIC_KEY_MULTIBASE in verificationMethod -> getPublicKeyObjectFromPublicKeyMultibase(
                    publicKeyStr, keyType
                )

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
