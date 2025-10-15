package io.mosip.vercred.vcverifier.credentialverifier.statusChecker

import com.fasterxml.jackson.databind.ObjectMapper
import foundation.identity.jsonld.JsonLDObject
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.data.CredentialStatusResult
import io.mosip.vercred.vcverifier.exception.StatusCheckException
import io.mosip.vercred.vcverifier.exception.StatusCheckErrorCode
import io.mosip.vercred.vcverifier.networkManager.HttpMethod.GET
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.logging.Logger
import java.util.zip.GZIPInputStream

/**
 * Generic StatusList2021 checker for LDP VCs.
 * Supports optional filtering by known statusPurposes.
 */
class LdpStatusChecker {

    private val logger = Logger.getLogger(LdpStatusChecker::class.java.name)
    private val minimumNumberOfEntries = 131072
    private val defaultStatusSize = 1
    private val mapper = ObjectMapper()

    /**
     * Checks one or more credentialStatus entries from a VC.
     *
     * @param credential The input VC JSON string.
     * @param statusPurposes Optional list of supported status purposes (e.g., ["revocation", "suspension"]).
     *                       If null, all credentialStatus entries will be checked.
     */
    fun getStatuses(
        credential: String,
        statusPurposes: List<String>? = null
    ): List<CredentialStatusResult>? {
        logger.info("Started status check")

        val jsonLD = JsonLDObject.fromJson(credential)
        val statusField = jsonLD.jsonObject["credentialStatus"] ?: return null

        val entries = when (statusField) {
            is List<*> -> statusField.filterIsInstance<Map<*, *>>()
            is Map<*, *> -> listOf(statusField)
            else -> emptyList()
        }

        if (entries.isEmpty()) {
            throw StatusCheckException(
                "No valid credentialStatus entries found",
                StatusCheckErrorCode.INVALID_PURPOSE
            )
        }

        // Filter entries based on supported purposes (if provided)
        val filteredEntries = statusPurposes?.let { supported ->
            entries.filter {
                val purpose = it["statusPurpose"]?.toString()?.lowercase()
                supported.map { p -> p.lowercase() }.contains(purpose)
            }
        } ?: entries

        if (filteredEntries.isEmpty()) {
            logger.warning("No matching credentialStatus entries found for supported purposes: $statusPurposes")
            return null
        }

        val results = mutableListOf<CredentialStatusResult>()
        filteredEntries.forEach { entry ->
            var purpose = ""
            try {
                 purpose =
                    entry["statusPurpose"]?.toString()?.lowercase() ?: throw StatusCheckException(
                        "statusPurpose Invalid",
                        errorCode = StatusCheckErrorCode.INVALID_PURPOSE
                    )
                results.add(checkStatusEntry(entry, purpose))
            } catch (e: Exception) {
                logger.warning("Status check failed for purpose '$purpose': ${e.message}")
                // Add a failure entry (optional, to keep track of skipped purposes)
                results.add(
                    CredentialStatusResult(
                        purpose = purpose,
                        statusListVC = "",
                        status = -1,
                        valid = false
                    )
                )
            }
        }
        return results
    }

    /**
     * Checks a single credentialStatus entry for its purpose.
     */
    private fun checkStatusEntry(entry: Map<*, *>, purpose: String): CredentialStatusResult {
        val statusListCredentialUrl = entry["statusListCredential"]?.toString()
            ?: throw StatusCheckException(
                "Missing 'statusListCredential'",
                StatusCheckErrorCode.INVALID_INDEX
            )
        val statusListIndex = entry["statusListIndex"]?.toString()?.toIntOrNull()
            ?: throw StatusCheckException(
                "Invalid or missing 'statusListIndex'",
                StatusCheckErrorCode.INVALID_INDEX
            )

        try {
            val statusListVCMap = sendHTTPRequest(statusListCredentialUrl, GET)
                ?: throw StatusCheckException(
                    "Retrieval of the status list failed",
                    StatusCheckErrorCode.STATUS_RETRIEVAL_ERROR
                )

            if (statusListVCMap["statusPurpose"]?.toString()?.lowercase() != purpose) {
                throw StatusCheckException(
                    "Status list VC purpose mismatch. Expected '$purpose', found '${statusListVCMap["statusPurpose"]}'",
                    StatusCheckErrorCode.STATUS_VERIFICATION_ERROR
                )
            }

            val statusListVCString = mapper.writeValueAsString(statusListVCMap)
            val statusListVC = JsonLDObject.fromJson(statusListVCString)
            val verifier = CredentialVerifierFactory().get(CredentialFormat.LDP_VC)

            if (!verifier.verify(statusListVCString)) {
                throw StatusCheckException(
                    "Invalid signature on status list VC",
                    StatusCheckErrorCode.STATUS_VERIFICATION_ERROR
                )
            }

            val credentialSubject = statusListVC.jsonObject["credentialSubject"] as? Map<*, *>
                ?: throw StatusCheckException(
                    "Missing 'credentialSubject'",
                    StatusCheckErrorCode.ENCODED_LIST_MISSING
                )

            val encodedList = credentialSubject["encodedList"] as? String
                ?: throw StatusCheckException(
                    "Missing 'encodedList'",
                    StatusCheckErrorCode.ENCODED_LIST_MISSING
                )

            val statusSize =
                credentialSubject["statusSize"]?.toString()?.toIntOrNull() ?: defaultStatusSize

            val decodedBitSet = decodeEncodedList(encodedList)
            val totalBits = decodedBitSet.size * 8
            if (totalBits < minimumNumberOfEntries * statusSize) {
                logger.warning("Decoded bitstring shorter than required herd privacy length")
            }

            val bitPosition = statusListIndex * statusSize
            if (bitPosition >= totalBits) {
                throw StatusCheckException(
                    "Bit position $bitPosition out of range",
                    StatusCheckErrorCode.RANGE_ERROR
                )
            }

            val isBitSet = readBit(bitPosition, decodedBitSet)
            return CredentialStatusResult(
                purpose = purpose,
                statusListVC = statusListVCString,
                status = if (isBitSet) 1 else 0,
                valid = isBitSet
            )

        } catch (e: StatusCheckException) {
            throw e
        } catch (e: Exception) {
            throw StatusCheckException(
                "Failed to check status for purpose '$purpose': ${e.message}",
                StatusCheckErrorCode.UNKNOWN_ERROR
            )
        }
    }

    private fun decodeEncodedList(encodedList: String): ByteArray {
        val actualEncoded = if (encodedList.startsWith("u")) encodedList else "u$encodedList"
        val base64urlPart = actualEncoded.substring(1)
        val compressedBytes = try {
            Base64Decoder().decodeFromBase64Url(base64urlPart)
        } catch (ex: IllegalArgumentException) {
            throw StatusCheckException(
                "Base64url decoding failed",
                StatusCheckErrorCode.BASE64_DECODE_FAILED
            )
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
            throw StatusCheckException(
                "Failed to decompress GZIP",
                StatusCheckErrorCode.GZIP_DECOMPRESS_FAILED
            )
        }
    }

    private fun readBit(position: Int, bitSet: ByteArray): Boolean {
        val byteIndex = position / 8
        val bitIndex = position % 8
        if (byteIndex >= bitSet.size) {
            throw StatusCheckException(
                "Position $position exceeds bitset length",
                StatusCheckErrorCode.RANGE_ERROR
            )
        }
        val targetByte = bitSet[byteIndex].toInt()
        return ((targetByte shr (7 - bitIndex)) and 1) == 1
    }
}
