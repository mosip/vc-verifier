package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DISCLOSURE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DISCLOSURE_STRUCTURE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_KB_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_VCT_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING_VCT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DISCLOSURE_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DISCLOSURE_STRUCTURE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_KB_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_VCT_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_VCT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.Util.isValidUri
import org.json.JSONArray
import org.json.JSONObject
import java.util.Date

class SdJwtValidator {
    companion object {
        private val SUPPORTED_SD_HASH_ALGORITHMS = setOf("sha-256", "sha-384", "sha-512")
        private val HASH_LENGTHS = mapOf(
            "sha-256" to 32,
            "sha-384" to 48,
            "sha-512" to 64
        )
        private val VALID_JWT_TYPES = setOf("vc+sd-jwt", "dc+sd-jwt")
    }

    fun validate(sdJwt: String): ValidationStatus {
        return try {
            validateAndProcess(sdJwt)
        } catch (e: ValidationException) {
            ValidationStatus(e.errorMessage, e.errorCode)
        } catch (e: Exception) {
            ValidationStatus(
                "$EXCEPTION_DURING_VALIDATION${e.message}",
                "${ERROR_CODE_INVALID}UNKNOWN"
            )
        }
    }

    private fun validateAndProcess(credential: String): ValidationStatus {
        if (credential.isBlank()) {
            throw ValidationException(ERROR_MESSAGE_EMPTY_VC_JSON, ERROR_CODE_EMPTY_VC_JSON)
        }
        val sdJwt = SDJWT.parse(credential)
        val issuerJwt = sdJwt.credentialJwt
        val disclosures = sdJwt.disclosures
        val keyBindingJwt = sdJwt.bindingJwt

        validateSDJwtStructure(issuerJwt, disclosures)
        keyBindingJwt?.let {
            validateKeyBindingJwt(it)
        }

        return ValidationStatus("", "")
    }

    private fun validateSDJwtStructure(issuerJwt: String, disclosures: List<Disclosure>) {
        val jwtParts = issuerJwt.split(".")
        if (jwtParts.size != 3) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_JWT_FORMAT,
                ERROR_CODE_INVALID_JWT_FORMAT
            )
        }
        val header = decodeBase64Json(jwtParts[0])
        val payload = decodeBase64Json(jwtParts[1])
        val payloadMap = jacksonObjectMapper().readValue(payload, Map::class.java)

        validateHeader(JSONObject(header))
        validatePayload(JSONObject(payload))
        validateDisclosures(disclosures, payloadMap)
    }

    private fun validateHeader(header: JSONObject) {
        val alg = header.optString("alg", "")
        if (alg.isBlank() && alg.equals("none", ignoreCase = true)) {
            throw ValidationException(
                "Missing or invalid 'alg' in JWT header",
                "${ERROR_CODE_INVALID}ALG"
            )
        }

        val typ = header.optString("typ", "")
        if (typ !in VALID_JWT_TYPES) {
            throw ValidationException(
                "Unsupported or missing 'typ' in JWT header",
                "${ERROR_CODE_INVALID}TYP"
            )
        }
    }

    private fun validatePayload(payload: JSONObject) {
        validateRequiredClaims(payload)
        validateTimeClaims(payload)
        validateUriClaims(payload)
        validateConfirmationClaim(payload)
    }

    private fun validateDisclosures(disclosures: List<Disclosure>, payload: Map<*, *>) {
        validateDisclosureFormat(disclosures)
        val hashAlg = (payload["_sd_alg"] as? String) ?: "sha-256"

        if (hashAlg !in SUPPORTED_SD_HASH_ALGORITHMS) {
            throw ValidationException(
                "Unsupported _sd_alg: $hashAlg. Allowed: $SUPPORTED_SD_HASH_ALGORITHMS",
                "${ERROR_CODE_INVALID}SD_ALG"
            )
        }

        val digestToDisclosure = disclosures.associateBy { it.digest(hashAlg) }
        val allSdDigests = mutableSetOf<String>()
        validateDisclosureSha(payload, digestToDisclosure, allSdDigests, hashAlg)
        val isAllDisclosureDigestPresent = digestToDisclosure.keys.all { it in allSdDigests }
        if (!isAllDisclosureDigestPresent)
            throw ValidationException(
                "Digest value of all disclosures must be present in the '_sd' claim of payload",
                "${ERROR_CODE_INVALID}DISCLOSURE"
            )

    }

    private fun validateRequiredClaims(payload: JSONObject) {
        val vct = payload.optString("vct", "")
        if (vct.isBlank()) {
            throw ValidationException(ERROR_MESSAGE_MISSING_VCT, ERROR_CODE_MISSING_VCT)
        }

        if (":" in vct && !isValidUri(vct)) {
            throw ValidationException(ERROR_MESSAGE_INVALID_VCT_URI, ERROR_CODE_INVALID_VCT_URI)
        }

        payload.optString("iss", "").takeIf { it.isNotBlank() }
            ?.let { iss ->
                if (!isValidUri(iss)) {
                    throw ValidationException("Invalid 'iss' claim: $iss", ERROR_CODE_INVALID)
                }
            }
    }

    private fun validateTimeClaims(payload: JSONObject) {
        payload.optLong("iat", -1).takeIf { it > 0 }?.let { iat ->
            if (DateUtils.isFutureDateWithTolerance(Date(iat * 1000).toString())) {
                throw ValidationException(
                    ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE,
                    ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE
                )
            }
        }

        payload.optLong("nbf", -1).takeIf { it > 0 }?.let { nbf ->
            if (DateUtils.isFutureDateWithTolerance(Date(nbf * 1000).toString())) {
                throw ValidationException(
                    ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE,
                    ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE
                )
            }
        }

        payload.optLong("exp", -1).takeIf { it > 0 }?.let { exp ->
            if (DateUtils.isVCExpired(Date(exp * 1000).toString())) {
                throw ValidationException(ERROR_MESSAGE_VC_EXPIRED, ERROR_CODE_VC_EXPIRED)
            }
        }
    }

    private fun validateUriClaims(payload: JSONObject) {
        listOf("aud", "nonce").forEach { field ->
            payload.optString(field, "").takeIf { it.isNotBlank() }
                ?.let { value ->
                    if (":" in value && !isValidUri(value)) {
                        throw ValidationException(
                            ERROR_INVALID_URI + value,
                            "${ERROR_CODE_INVALID}${field.uppercase()}"
                        )
                    }
                }
        }
    }

    private fun validateConfirmationClaim(payload: JSONObject) {
        payload.optJSONObject("cnf")?.let { cnf ->
            if (cnf.has("jwk") && cnf.has("kid")) {
                throw ValidationException(
                    "Invalid 'cnf' object: must contain either 'jwk' or 'kid'",
                    "${ERROR_CODE_INVALID}CNF"
                )
            }
        }
    }

    private fun validateDisclosureFormat(disclosures: List<Disclosure>) {
        disclosures.forEachIndexed { index, encodedDisclosure ->
            val jsonArray = try {
                val decodedBytes = Base64Decoder().decodeFromBase64Url(encodedDisclosure.disclosure)
                JSONArray(String(decodedBytes))
            } catch (e: Exception) {
                throw ValidationException(
                    "$ERROR_MESSAGE_INVALID_DISCLOSURE_FORMAT at index $index",
                    ERROR_CODE_INVALID_DISCLOSURE_FORMAT
                )
            }

            when (jsonArray.length()) {
                2 -> { /* Valid array disclosure */
                }

                3 -> validateObjectDisclosure(jsonArray, index)
                else -> throw ValidationException(
                    "$ERROR_MESSAGE_INVALID_DISCLOSURE_STRUCTURE at index $index",
                    ERROR_CODE_INVALID_DISCLOSURE_STRUCTURE
                )
            }
        }
    }

    private fun validateObjectDisclosure(jsonArray: JSONArray, index: Int) {
        val name = jsonArray.optString(1, null)
        if (name == null || name.startsWith("_")) {
            throw ValidationException(
                "$ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME at index $index",
                ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME
            )
        }
    }

    private fun validateDisclosureSha(
        node: Any?,
        digestToDisclosure: Map<String, Disclosure>,
        allSdDigests: MutableSet<String>,
        hashAlg: String
    ): Any? {
        return when (node) {
            is Map<*, *> -> {
                val mutableNode = node.toMutableMap() as MutableMap<String, Any?>
                (mutableNode["_sd"] as? List<*>)?.forEach { digest ->
                    val digestStr = digest as? String ?: return@forEach
                    validateDigests(digest, hashAlg)
                    allSdDigests += digestStr
                    val disclosure = digestToDisclosure[digestStr] ?: return@forEach
                    val claimName = disclosure.claimName
                    val claimValue = disclosure.claimValue
                    if (!mutableNode.containsKey(claimName)) {
                        mutableNode[claimName] = claimValue
                    }
                }
                mutableNode.remove("_sd")

                for ((key, value) in mutableNode) {
                    mutableNode[key] =
                        validateDisclosureSha(value, digestToDisclosure, allSdDigests, hashAlg)
                }
                mutableNode
            }

            is List<*> -> {
                node.map { item ->
                    validateDisclosureSha(item, digestToDisclosure, allSdDigests, hashAlg)
                }
            }

            else -> {
                node
            }
        }
    }

    private fun validateDigests(digest: String, sdAlg: String) {
        val expectedLength = HASH_LENGTHS[sdAlg.lowercase()]!!
        if (digest.isBlank()) {
            throw ValidationException(
                "Invalid digest: must be a non-empty string",
                "${ERROR_CODE_INVALID}DIGEST"
            )
        }

        val decoded: ByteArray
        try {
            decoded = Base64Decoder().decodeFromBase64Url(digest)
        } catch (e: Exception) {
            throw ValidationException(
                "Invalid base64url encoding in digest: $digest ${e.message}",
                "${ERROR_CODE_INVALID}DIGEST"
            )
        }
        if (decoded.size != expectedLength) {
            throw ValidationException(
                "Invalid digest length of digest: expected $expectedLength bytes, got ${decoded.size}",
                "${ERROR_CODE_INVALID}DIGEST"
            )
        }

    }

    private fun validateKeyBindingJwt(kbJwt: String) {
        val parts = kbJwt.split(".")
        if (parts.size != 3) {
            throw ValidationException(
                ERROR_MESSAGE_INVALID_KB_JWT_FORMAT,
                ERROR_CODE_INVALID_KB_JWT_FORMAT
            )
        }

        val payload = JSONObject(decodeBase64Json(parts[1]))
        validateKeyBindingPayload(payload)
    }

    private fun validateKeyBindingPayload(payload: JSONObject) {
        val requiredFields = listOf("aud", "nonce", "cnf")

        requiredFields.forEach { field ->
            if (!payload.has(field)) {
                throw ValidationException(
                    "Missing '$field' in Key Binding JWT",
                    "${ERROR_CODE_INVALID}${field.uppercase()}"
                )
            }
        }

        val aud = payload.optString("aud")
        if (aud.isBlank()) {
            throw ValidationException(
                "'aud' in Key Binding JWT must be a non-empty string",
                "${ERROR_CODE_INVALID}AUD"
            )
        }

        if (":" in aud && !isValidUri(aud)) {
            throw ValidationException(
                "'aud' in Key Binding JWT must be a valid URI when containing ':'",
                "${ERROR_CODE_INVALID}AUD"
            )
        }

        val nonce = payload.optString("nonce")
        if (nonce.isBlank()) {
            throw ValidationException(
                "'nonce' in Key Binding JWT must be a non-empty string",
                "${ERROR_CODE_INVALID}NONCE"
            )
        }

        val cnf = payload.optJSONObject("cnf")
        if (cnf == null || (!cnf.has("jwk") && !cnf.has("kid"))) {
            throw ValidationException(
                "Invalid or missing 'cnf' in Key Binding JWT",
                "${ERROR_CODE_INVALID}CNF"
            )
        }
    }

    private fun decodeBase64Json(encoded: String): String {
        val decodedBytes = Base64Decoder().decodeFromBase64Url(encoded)
        return String(decodedBytes)
    }
}