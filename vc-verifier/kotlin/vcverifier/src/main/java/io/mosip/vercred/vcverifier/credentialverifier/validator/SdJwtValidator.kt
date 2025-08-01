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
import io.mosip.vercred.vcverifier.utils.Util.isValidUri
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

        header.optString("alg", "")
            .takeIf { it.isNotBlank() && !it.equals("none", ignoreCase = true) }
            ?: throw ValidationException(
                "Missing or invalid 'alg' in JWT header",
                ERROR_CODE_INVALID
            )

        header.optString("typ", "").takeIf { it == "vc+sd-jwt" || it == "dc+sd-jwt" }
            ?: throw ValidationException(
                "Unsupported or missing 'typ' in JWT header",
                ERROR_CODE_INVALID
            )
    }

    private fun validateIssuerJwtPayload(payload: JSONObject, disclosures: List<String>) {
        val vct = payload.optString("vct", "").takeIf { it.isNotBlank() }
            ?: throw ValidationException(ERROR_MESSAGE_MISSING_VCT, ERROR_CODE_MISSING_VCT)

        if (":" in vct && !isValidUri(vct)) {
            throw ValidationException(ERROR_MESSAGE_INVALID_VCT_URI, ERROR_CODE_INVALID_VCT_URI)
        }


        payload.optString("iss", "").takeIf { it.isNotBlank() }
            ?.let { iss ->
                if (!isValidUri(iss)) {
                    throw ValidationException("Invalid 'iss' claim: $iss", ERROR_CODE_INVALID)
                }
            }

        payload.optLong("iat", -1).takeIf { it > 0 }
            ?.let { iat ->
                if (DateUtils.isFutureDateWithTolerance(DateUtils.epochSecondsToISOString(iat))) {
                    throw ValidationException(
                        "Invalid or future 'iat'",
                        ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
                    )
                }
            }

        payload.optLong("nbf", -1).takeIf { it > 0 }
            ?.let { nbf ->
                if (DateUtils.isFutureDateWithTolerance(DateUtils.epochSecondsToISOString(nbf))) {
                    throw ValidationException(
                        "Invalid or future 'nbf'",
                        ERROR_CURRENT_DATE_BEFORE_VALID_FROM
                    )
                }
            }

        payload.optLong("exp", -1).takeIf { it > 0 }
            ?.let { exp ->
                if (DateUtils.isVCExpired(DateUtils.epochSecondsToISOString(exp))) {
                    throw ValidationException(ERROR_MESSAGE_VC_EXPIRED, ERROR_CODE_VC_EXPIRED)
                }
            }

        listOf("aud", "nonce").forEach { field ->
            payload.optString(field, "").takeIf { it.isNotBlank() }
                ?.let { value ->
                    if (":" in value && !isValidUri(value)) {
                        throw ValidationException(ERROR_INVALID_URI + value, ERROR_CODE_INVALID)
                    }
                }
        }

        payload.optJSONObject("cnf")?.takeIf { !it.has("jwk") && !it.has("kid") }
            ?.let {
                throw ValidationException(
                    "Invalid 'cnf' object: must contain either 'jwk' or 'kid'",
                    ERROR_CODE_INVALID
                )
            }

        payload.optString("_sd_alg", "")
            .takeIf { it.isNotBlank() && it !in SUPPORTED_SD_HASH_ALGORITHMS }?.let { sdAlg ->
                throw ValidationException(
                    "Unsupported _sd_alg: $sdAlg. Allowed: $SUPPORTED_SD_HASH_ALGORITHMS",
                    ERROR_CODE_INVALID
                )
            }

        if (disclosures.isNotEmpty()) {
            if (!payload.has("_sd")) {
                throw ValidationException(
                    "Missing required '_sd' claim when disclosures are present",
                    ERROR_CODE_INVALID
                )
            }
            val sdAlg = payload.optString("_sd_alg", "sha-256")

            val sdArray = payload.optJSONArray("_sd")
            if (sdArray == null || sdArray.length() != disclosures.size) {
                throw ValidationException(
                    "Mismatch between number of disclosures (${disclosures.size}) and _sd entries (${sdArray?.length() ?: 0})",
                    ERROR_CODE_INVALID
                )
            }

            val expectedHashLength = getExpectedHashLength(sdAlg)

            for (i in 0 until sdArray.length()) {
                val digest = sdArray.optString(i).takeIf { !it.isNullOrBlank() }
                    ?: throw ValidationException(
                        "Invalid digest at _sd[$i]: must be a non-empty string",
                        ERROR_CODE_INVALID
                    )

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

    private fun getExpectedHashLength(sdAlg: String): Int {
        return when (sdAlg.lowercase()) {
            "sha-256" -> 32
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

        requiredFields.forEach { field ->
            if (!payload.has(field)) {
                throw ValidationException("Missing '$field' in Key Binding JWT", ERROR_CODE_INVALID)
            }
        }

        val aud = payload.optString("aud").takeIf { it.isNotBlank() }
            ?: throw ValidationException(
                "'aud' in Key Binding JWT must be a non-empty string",
                ERROR_CODE_INVALID
            )

        if (":" in aud && !isValidUri(aud)) {
            throw ValidationException(
                "'aud' in Key Binding JWT must be a valid URI when containing ':'",
                ERROR_CODE_INVALID
            )
        }

        payload.optString("nonce").ifBlank {
            throw ValidationException(
                "'nonce' in Key Binding JWT must be a non-empty string",
                ERROR_CODE_INVALID
            )
        }

        payload.optJSONObject("cnf")?.takeIf { it.has("jwk") || it.has("kid") }
            ?: throw ValidationException(
                "Invalid or missing 'cnf' in Key Binding JWT",
                ERROR_CODE_INVALID
            )
    }
}
