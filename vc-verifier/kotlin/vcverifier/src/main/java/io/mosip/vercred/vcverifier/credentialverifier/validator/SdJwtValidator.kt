package io.mosip.vercred.vcverifier.credentialverifier.validator


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
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_VALID_FROM
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
import org.json.JSONArray
import org.json.JSONObject

class SdJwtValidator {
    private val SUPPORTED_SD_HASH_ALGORITHMS = setOf("sha-256", "sha-384", "sha-512")

    fun validate(sdJwt: String): ValidationStatus {
        try {
            if (sdJwt.isBlank()) {
                throw ValidationException(ERROR_MESSAGE_EMPTY_VC_JSON, ERROR_CODE_EMPTY_VC_JSON)
            }

            val parts = sdJwt.split("~")
            val issuerJwt = parts[0]
            val hasKb = !sdJwt.endsWith("~")

            val rawDisclosures =
                if (hasKb) parts.subList(1, parts.size - 1) else parts.subList(1, parts.size)
            val disclosures = rawDisclosures.filter { it.isNotBlank() }
            val kbJwt = if (hasKb) parts.lastOrNull() else null

            val jwtParts = issuerJwt.split(".")
            if (jwtParts.size != 3) {
                throw ValidationException(
                    ERROR_MESSAGE_INVALID_JWT_FORMAT,
                    ERROR_CODE_INVALID_JWT_FORMAT
                )
            }

            val headerJson = decodeBase64Json(jwtParts[0])
            val payloadJson = decodeBase64Json(jwtParts[1])

            validateHeader(headerJson)
            validateIssuerJwtPayload(payloadJson, disclosures)
            validateDisclosureSyntax(disclosures)

            if (kbJwt != null) {
                validateKeyBindingJwt(kbJwt)
            }

            return ValidationStatus("", "")
        } catch (e: ValidationException) {
            return ValidationStatus(e.errorMessage, e.errorCode)
        } catch (e: Exception) {
            return ValidationStatus("$EXCEPTION_DURING_VALIDATION${e.message}", ERROR_CODE_INVALID)
        }
    }

    private fun decodeBase64Json(encoded: String): JSONObject {
        val decodedBytes = Base64Decoder().decodeFromBase64Url(encoded)
        return JSONObject(String(decodedBytes))
    }

    private fun validateHeader(header: JSONObject) {
        if (!header.has("alg")) {
            throw ValidationException("Missing 'alg' in JWT header", ERROR_CODE_INVALID)
        }
        val alg = header.optString("alg", null)
        if (alg.isBlank() || alg.equals("none", ignoreCase = true)) {
            throw ValidationException(
                "Invalid or insecure 'alg' value in JWT header: $alg",
                ERROR_CODE_INVALID
            )
        }
        if (!header.has("typ")) {
            throw ValidationException("Missing 'typ' in JWT header", ERROR_CODE_INVALID)
        }
        val typ = header.getString("typ")
        if (typ != "vc+sd-jwt" && typ != "dc+sd-jwt") {
            throw ValidationException("Unsupported JWT typ: $typ", ERROR_CODE_INVALID)
        }
    }

    private fun validateIssuerJwtPayload(payload: JSONObject, disclosures: List<String>) {
        val vct = payload.optString("vct", null)
        if (vct.isNullOrBlank()) {
            throw ValidationException(ERROR_MESSAGE_MISSING_VCT, ERROR_CODE_MISSING_VCT)
        }

        if (":" in vct && !isValidUri(vct)) {
            throw ValidationException(ERROR_MESSAGE_INVALID_VCT_URI, ERROR_CODE_INVALID_VCT_URI)
        }

        if (payload.has("iss")) {
            val iss = payload.optString("iss", null)
            if (iss.isNullOrBlank() || !(isDid(iss) || isValidUri(iss))) {
                throw ValidationException("Invalid 'iss' claim: $iss", ERROR_CODE_INVALID)
            }
        }

        payload.optLong("iat", -1).takeIf { it > 0 }?.let { iat ->
            if (DateUtils.isFutureDateWithTolerance(DateUtils.epochSecondsToISOString(iat))) {
                throw ValidationException(
                    "Invalid or future 'iat'",
                    ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
                )
            }
        }

        payload.optLong("nbf", -1).takeIf { it > 0 }?.let { nbf ->
            if (DateUtils.isFutureDateWithTolerance(DateUtils.epochSecondsToISOString(nbf))) {
                throw ValidationException(
                    "Invalid or future 'nbf'",
                    ERROR_CURRENT_DATE_BEFORE_VALID_FROM
                )
            }
        }

        payload.optLong("exp", -1).takeIf { it > 0 }?.let { exp ->
            if (DateUtils.isVCExpired(DateUtils.epochSecondsToISOString(exp))) {
                throw ValidationException(ERROR_MESSAGE_VC_EXPIRED, ERROR_CODE_VC_EXPIRED)
            }
        }

        listOf("aud", "nonce").forEach { field ->
            payload.optString(field, null)?.takeIf { it.isNotBlank() }?.let { value ->
                if (":" in value && !isValidUri(value)) {
                    throw ValidationException(ERROR_INVALID_URI + value, ERROR_CODE_INVALID)
                }
            }
        }

        payload.optJSONObject("cnf")?.let { cnf ->
            if (!cnf.has("jwk") && !cnf.has("kid")) {
                throw ValidationException(
                    "Invalid 'cnf' object: must contain either 'jwk' or 'kid'",
                    ERROR_CODE_INVALID
                )
            }
        }

        payload.optString("_sd_alg", null)?.let { sdAlg ->
            if (sdAlg.isNotBlank() && sdAlg !in SUPPORTED_SD_HASH_ALGORITHMS) {
                throw ValidationException(
                    "Unsupported _sd_alg: $sdAlg. Allowed: $SUPPORTED_SD_HASH_ALGORITHMS",
                    ERROR_CODE_INVALID
                )
            }
        }

        if (disclosures.isNotEmpty()) {
            if (!payload.has("_sd")) {
                throw ValidationException(
                    "Missing required '_sd' claim when disclosures are present",
                    ERROR_CODE_INVALID
                )
            }

            val sdAlg = payload.optString("_sd_alg", null)
            val expectedHashLength = getExpectedHashLength(sdAlg)

            val sdArray = payload.optJSONArray("_sd")
            if (sdArray == null || sdArray.length() != disclosures.size) {
                throw ValidationException(
                    "Mismatch between number of disclosures (${disclosures.size}) and _sd entries (${sdArray?.length() ?: 0})",
                    ERROR_CODE_INVALID
                )
            }

            for (i in 0 until sdArray.length()) {
                val digest = sdArray.optString(i, null)
                if (digest.isNullOrBlank()) {
                    throw ValidationException(
                        "Invalid digest at _sd[$i]: must be a non-empty string",
                        ERROR_CODE_INVALID
                    )
                }
                try {
                    val decoded = Base64Decoder().decodeFromBase64Url(digest)
                    if (decoded.size != expectedHashLength) {
                        throw ValidationException(
                            "Invalid digest length at _sd[$i]: expected $expectedHashLength bytes, got ${decoded.size}",
                            ERROR_CODE_INVALID
                        )
                    }
                } catch (e: Exception) {
                    throw ValidationException(
                        "Invalid base64url encoding in _sd[$i]: $digest ${e.message}",
                        ERROR_CODE_INVALID
                    )
                }
            }

        }


    }

    private fun validateDisclosureSyntax(disclosures: List<String>) {
        disclosures.forEachIndexed { index, encodedDisclosure ->
            val json = try {
                val decodedBytes = Base64Decoder().decodeFromBase64Url(encodedDisclosure)
                JSONArray(String(decodedBytes))
            } catch (e: Exception) {
                throw ValidationException(
                    "$ERROR_MESSAGE_INVALID_DISCLOSURE_FORMAT at index $index",
                    ERROR_CODE_INVALID_DISCLOSURE_FORMAT
                )
            }

            when (json.length()) {
                3 -> {
                    val name = json.optString(1, null)
                    if (name == null || name.startsWith("_")) {
                        throw ValidationException(
                            "$ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME at index $index",
                            ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME
                        )
                    }
                }

                2 -> {}
                else -> {
                    throw ValidationException(
                        "$ERROR_MESSAGE_INVALID_DISCLOSURE_STRUCTURE at index $index",
                        ERROR_CODE_INVALID_DISCLOSURE_STRUCTURE
                    )
                }
            }
        }
    }

    private fun isValidUri(value: String): Boolean {
        return try {
            val uri = java.net.URI(value)
            uri.scheme != null
        } catch (e: Exception) {
            false
        }
    }

    private fun isDid(value: String): Boolean {
        return value.startsWith("did:")
    }

    private fun getExpectedHashLength(sdAlg: String?): Int {
        return when (sdAlg?.lowercase()) {
            "sha-256", null -> 32
            "sha-384" -> 48
            "sha-512" -> 64
            else -> throw ValidationException("Unsupported _sd_alg: $sdAlg", ERROR_CODE_INVALID)
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

        val payload = decodeBase64Json(parts[1])
        val requiredFields = listOf("aud", "nonce", "cnf")

        for (field in requiredFields) {
            if (!payload.has(field)) {
                throw ValidationException("Missing '$field' in Key Binding JWT", ERROR_CODE_INVALID)
            }
        }

        val aud = payload.optString("aud")
        if (aud.isBlank()) {
            throw ValidationException(
                "'aud' in Key Binding JWT must be a non-empty string",
                ERROR_CODE_INVALID
            )
        }
        if (":" in aud && !isValidUri(aud)) {
            throw ValidationException(
                "'aud' in Key Binding JWT must be a valid URI when containing ':'",
                ERROR_CODE_INVALID
            )
        }

        val nonce = payload.optString("nonce")
        if (nonce.isBlank()) {
            throw ValidationException(
                "'nonce' in Key Binding JWT must be a non-empty string",
                ERROR_CODE_INVALID
            )
        }

        val cnf = payload.optJSONObject("cnf")
        if (cnf == null || (!cnf.has("jwk") && !cnf.has("kid"))) {
            throw ValidationException(
                "Invalid or missing 'cnf' in Key Binding JWT",
                ERROR_CODE_INVALID
            )
        }
    }
}
