package io.mosip.vercred.vcverifier.publicKey.impl

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFICATION_METHOD
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetter
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPemPublicKey
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPublicKeyMultibase
import io.mosip.vercred.vcverifier.publicKey.isPemPublicKey
import io.mosip.vercred.vcverifier.publicKey.isPublicKeyMultibase
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.URI
import java.security.PublicKey

class DidWebPublicKeyGetter: PublicKeyGetter {

    private val RESOLVER_API = "https://resolver.identity.foundation/1.0/identifiers/"

    override fun get(verificationMethod: URI): PublicKey {
        val resolverUrl = "$RESOLVER_API$verificationMethod"
        try {
            val request = Request.Builder()
                .url(resolverUrl)
                .get()
                .build()
            val response = OkHttpClient.Builder().build().newCall(request).execute()
            response.body?.use { responseBody ->
                val jsonNode = ObjectMapper().readTree(responseBody.string())
                if (jsonNode.isObject) {
                    val publicKeyStr = getKeyValue(jsonNode as ObjectNode,PUBLIC_KEY_MULTIBASE )
                    val keyType = getKeyValue(jsonNode, KEY_TYPE )
                    return when {
                        isPemPublicKey(publicKeyStr) -> getPublicKeyObjectFromPemPublicKey(publicKeyStr, keyType)
                        isPublicKeyMultibase(publicKeyStr) -> getPublicKeyObjectFromPublicKeyMultibase(publicKeyStr, keyType)
                        else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
                    }

                }
            }


            throw PublicKeyNotFoundException("Public key string not found")
        } catch (e: Exception) {
            //logger.severe("Error fetching public key string $e")
            throw PublicKeyNotFoundException("Public key string not found")
        }
    }

    private fun getKeyValue(responseObjectNode: ObjectNode, key: String): String =
        responseObjectNode.get("didDocument")
            .get(VERIFICATION_METHOD)[0].get(key).asText()
}