package io.mosip.vercred.vcverifier.publicKey.impl

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
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

class HttpsPublicKeyGetter : PublicKeyGetter {
    override fun get(verificationMethod: URI): PublicKey {
        try {
            val okHttpClient = OkHttpClient.Builder().build().newBuilder().build()
            val request = Request.Builder()
                .url(verificationMethod.toURL())
                .get()
                .build()

            val response = okHttpClient.newCall(request).execute()
            response.body?.let { responseBody ->
                val objectMapper = ObjectMapper()
                val jsonNode = objectMapper.readTree(responseBody.string())
                val responseObjectNode = jsonNode as ObjectNode
                val publicKeyStr =
                    responseObjectNode[CredentialVerifierConstants.PUBLIC_KEY_PEM].asText()
                val keyType = responseObjectNode[CredentialVerifierConstants.KEY_TYPE].asText()
                return when {
                    isPemPublicKey(publicKeyStr) -> getPublicKeyObjectFromPemPublicKey(publicKeyStr, keyType)
                    isPublicKeyMultibase(publicKeyStr) -> getPublicKeyObjectFromPublicKeyMultibase(publicKeyStr, keyType)
                    else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
                }
            }
            throw PublicKeyNotFoundException("Public key string not found")
        } catch (e: Exception) {
            //logger.severe("Error fetching public key string $e")
            throw PublicKeyNotFoundException("Public key string not found")

        }
    }

}