package io.mosip.vercred.vcverifier.credentialverifier.verifier

import foundation.identity.jsonld.JsonLDObject

class StatusListRevocationChecker : RevocationChecker {

    override fun isRevoked(credential: JsonLDObject): Boolean {

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
        val fullUrl = "$baseUrl?statusPurpose=$statusPurpose&statusListIndex=$statusListIndex"
        return try {
            val url = java.net.URL(fullUrl)
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "application/json")
            conn.connectTimeout = 3000
            conn.readTimeout = 3000

            val responseCode = conn.responseCode
            if (responseCode != 200) {
                return false
            }

            val response = conn.inputStream.bufferedReader().use { it.readText() }

            response.contains("\"status\":\"revoked\"")

        } catch (e: Exception) {
            println("Failed to check revocation: ${e.message}")
            false
        }
    }
}
