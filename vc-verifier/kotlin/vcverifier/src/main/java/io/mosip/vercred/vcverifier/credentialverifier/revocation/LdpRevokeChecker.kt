package io.mosip.vercred.vcverifier.credentialverifier.revocation

import foundation.identity.jsonld.JsonLDObject
import java.lang.RuntimeException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.zip.GZIPInputStream
import java.util.logging.Logger

import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.exception.*
import io.mosip.vercred.vcverifier.networkManager.HTTP_METHOD.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import com.fasterxml.jackson.databind.ObjectMapper

class LdpRevokeChecker  {
    private val logger = Logger.getLogger(LdpRevokeChecker::class.java.name)

     fun isRevoked(credential: String): Boolean {
        logger.info("Started revocation check")
        val jsonLD = JsonLDObject.fromJson(credential)
        val credentialStatus = jsonLD.jsonObject["credentialStatus"] as? Map<*, *> ?: return false

        val statusListCredentialUrl = credentialStatus["statusListCredential"]?.toString()
            ?: throw IllegalArgumentException("Missing 'statusListCredential'")
        val statusListIndex = credentialStatus["statusListIndex"]?.toString()?.toIntOrNull()
            ?: throw IllegalArgumentException("Invalid or missing 'statusListIndex'")

        logger.info("statusListCredential URL: $statusListCredentialUrl")
        logger.info("statusListIndex: $statusListIndex")

        try {
            val statusListVCMap = sendHTTPRequest(statusListCredentialUrl, GET)
                ?: throw StatusListFetchException("Failed to fetch status list VC from $statusListCredentialUrl")

            val statusListVCString = ObjectMapper().writeValueAsString(statusListVCMap)
            val statusListVC = JsonLDObject.fromJson(statusListVCString)

            val credentialVerifier = CredentialVerifierFactory().get(CredentialFormat.LDP_VC)
            if (!credentialVerifier.verify(statusListVCString)) {
                throw SignatureVerificationException("Invalid signature on status list VC")
            }

            val encodedList = (statusListVC.jsonObject["credentialSubject"] as? Map<*, *>)?.get("encodedList") as? String
                ?: throw EncodedListMissingException("Missing 'encodedList' in status list VC")

            val decodedBitSet = decodeEncodedList(encodedList)
            return isIndexRevoked(statusListIndex, decodedBitSet)

        } catch (e: Exception) {
            throw RevocationCheckException("Failed to check revocation: ${e.message}")
        }
    }

    private fun isIndexRevoked(index: Int, bitSet: ByteArray): Boolean {
        val byteIndex = index / 8
        val bitIndex = index % 8

        if (byteIndex >= bitSet.size) {
            throw IndexOutOfBoundsException("Index $index exceeds decoded bitset length ${bitSet.size * 8}")
        }

        val targetByte = bitSet[byteIndex].toInt()
        return ((targetByte shr (7 - bitIndex)) and 1) == 1
    }

    private fun decodeEncodedList(encodedList: String): ByteArray {
        val actualEncoded = if (encodedList.startsWith("u")) encodedList else "u$encodedList"
        val base64urlPart = actualEncoded.substring(1)

        val compressedBytes = try {
            Base64Decoder().decodeFromBase64UrlFormatEncoded(base64urlPart)
        } catch (ex: IllegalArgumentException) {
            throw RuntimeException("Base64url decoding failed", ex)
        }

        return decompressGzip(compressedBytes)
    }

    private fun decompressGzip(compressed: ByteArray): ByteArray {
        try {
            ByteArrayInputStream(compressed).use { bais ->
                GZIPInputStream(bais).use { gzipIS ->
                    val baos = ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    var bytesRead: Int
                    while (gzipIS.read(buffer).also { bytesRead = it } != -1) {
                        baos.write(buffer, 0, bytesRead)
                    }
                    return baos.toByteArray()
                }
            }
        } catch (ex: IOException) {
            throw RuntimeException("Failed to decompress GZIP", ex)
        }
    }

}
