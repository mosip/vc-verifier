package io.mosip.vercred.vcverifier.credentialverifier.revocation

import foundation.identity.jsonld.JsonLDObject
import java.lang.RuntimeException
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.springframework.web.util.UriComponentsBuilder

class StatusListRevocationChecker : RevocationChecker {
    companion object {
        private const val TIMEOUT_MS = 3000
    }

    class RevokedCredentialException(message: String) : RuntimeException(message)

    override fun isRevoked(credential: String): Boolean {
        val credential: JsonLDObject = JsonLDObject.fromJson(credential)
        val credentialStatus = credential.jsonObject["credentialStatus"]

        if (credentialStatus == null) {
            return false
        }

        if (credentialStatus !is Map<*, *>) {
            throw IllegalArgumentException("Invalid 'credentialStatus' field: must be a map")
        }

        val baseUrl = credentialStatus["statusListCredential"]?.toString()
        val statusListIndex = credentialStatus["statusListIndex"]?.toString()
        val statusPurpose = credentialStatus["statusPurpose"]?.toString() ?: "revocation"

        if (baseUrl.isNullOrBlank() || statusListIndex.isNullOrBlank()) {
            throw IllegalArgumentException("Invalid credentialStatus format")
        }

        val fullUrl = UriComponentsBuilder.fromHttpUrl(baseUrl)
            .queryParam("statusPurpose", statusPurpose)
            .queryParam("statusListIndex", statusListIndex)
            .build()
            .toUriString()

        try {
            val url = java.net.URL(fullUrl)
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "application/json")
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS

            val responseCode = conn.responseCode
            if (responseCode != 200) {
                throw RuntimeException("Failed to fetch revocation status: HTTP $responseCode")
            }

            val response = conn.inputStream.bufferedReader().use { it.readText() }

            val mapper = jacksonObjectMapper()
            val jsonMap: Map<String, Any?> = mapper.readValue(response)
            val status = jsonMap["status"]

            if (status == "revoked") {
                return true
            }

        } catch (e: RevokedCredentialException) {
            throw e
        } catch (e: Exception) {
            throw RuntimeException("Failed to check revocation: ${e.message}", e)
        }

        return false
    }
}
