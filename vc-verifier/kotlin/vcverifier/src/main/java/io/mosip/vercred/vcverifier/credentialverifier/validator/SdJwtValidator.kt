package io.mosip.vercred.vcverifier.credentialverifier.validator

import com.authlete.sd.Disclosure
import com.authlete.sd.SDJWT
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
            ValidationStatus("", "")
        } catch (e: ValidationException) {
            ValidationStatus(e.errorMessage, e.errorCode)
        } catch (e: Exception) {
            ValidationStatus("$EXCEPTION_DURING_VALIDATION${e.message}", ERROR_CODE_INVALID)
        }
    }

    private fun validateAndProcess(credential: String) {
        require(credential.isNotBlank()) {
            ValidationException(ERROR_MESSAGE_EMPTY_VC_JSON, ERROR_CODE_EMPTY_VC_JSON)
        }
        val sdJwt = SDJWT.parse(credential)
        val issuerJwt = sdJwt.credentialJwt
        val disclosures = sdJwt.disclosures
        val keyBindingJwt = sdJwt.bindingJwt

        validateSDJwtStructure(issuerJwt, disclosures)
        keyBindingJwt?.let {
            validateKeyBindingJwt(it)
        }
    }

    private fun validateSDJwtStructure(issuerJwt: String, disclosures: List<Disclosure>) {
        val jwtParts = issuerJwt.split(".")
        require(jwtParts.size == 3) {
            ValidationException(ERROR_MESSAGE_INVALID_JWT_FORMAT, ERROR_CODE_INVALID_JWT_FORMAT)
        }
        val header = decodeBase64Json(jwtParts[0])
        val payload = decodeBase64Json(jwtParts[1])
        val payloadMap = mapper.readValue(payload, Map::class.java)

        validateHeader(JSONObject(header))
        validatePayload(JSONObject(payload), disclosures)
        validateDisclosures(disclosures, payloadMap)
    }

    private fun validateHeader(header: JSONObject) {
        val alg = header.optString("alg", "")
        require(alg.isNotBlank() && !alg.equals("none", ignoreCase = true)) {
            ValidationException("Missing or invalid 'alg' in JWT header", ERROR_CODE_INVALID)
        }

        val typ = header.optString("typ", "")
        require(typ in VALID_JWT_TYPES) {
            ValidationException("Unsupported or missing 'typ' in JWT header", ERROR_CODE_INVALID)
        }
    }

    private fun validatePayload(payload: JSONObject, disclosures: List<Disclosure>) {
        validateRequiredClaims(payload)
        validateTimeClaims(payload)
        validateUriClaims(payload)
        validateConfirmationClaim(payload)
        validateSelectiveDisclosure(payload, disclosures)
    }

    private fun validateDisclosures(disclosures: List<Disclosure>, payload: Map<*, *>) {
        validateDisclosureFormat(disclosures)
        val hashAlg = (payload["_sd_alg"] as? String) ?: "sha-256"
        val digestToDisclosure = disclosures.associateBy { it.digest(hashAlg) }
        val allSdDigests = mutableSetOf<String>()
        validateDisclosureSha(payload, digestToDisclosure, allSdDigests)
        val isAllDisclosureDigestPresent = digestToDisclosure.keys.all { it in allSdDigests }
        if (!isAllDisclosureDigestPresent)
            throw ValidationException(
                "Digest value of all disclosures must be present in the '_sd' claim of payload",
                "${ERROR_CODE_INVALID}DISCLOSURE"
            )

    }

    private fun validateRequiredClaims(payload: JSONObject) {
        val vct = payload.optString("vct", "")
        require(vct.isNotBlank()) {
            ValidationException(ERROR_MESSAGE_MISSING_VCT, ERROR_CODE_MISSING_VCT)
        }

        if (":" in vct) {
            require(isValidUri(vct)) {
                ValidationException(ERROR_MESSAGE_INVALID_VCT_URI, ERROR_CODE_INVALID_VCT_URI)
            }
        }

        payload.optString("iss", "").takeIf { it.isNotBlank() }
            ?.let { iss ->
                require(isValidUri(iss)) {
                    ValidationException("Invalid 'iss' claim: $iss", ERROR_CODE_INVALID)
                }
            }
    }

    private fun validateTimeClaims(payload: JSONObject) {
        payload.optLong("iat", -1).takeIf { it > 0 }?.let { iat ->
            require(!DateUtils.isFutureDateWithTolerance(DateUtils.epochSecondsToISOString(iat))) {
                ValidationException("Invalid or future 'iat'", ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE)
            }
        }

        payload.optLong("nbf", -1).takeIf { it > 0 }?.let { nbf ->
            require(!DateUtils.isFutureDateWithTolerance(DateUtils.epochSecondsToISOString(nbf))) {
                ValidationException("Invalid or future 'nbf'", ERROR_CURRENT_DATE_BEFORE_VALID_FROM)
            }
        }

        payload.optLong("exp", -1).takeIf { it > 0 }?.let { exp ->
            require(!DateUtils.isVCExpired(DateUtils.epochSecondsToISOString(exp))) {
                ValidationException(ERROR_MESSAGE_VC_EXPIRED, ERROR_CODE_VC_EXPIRED)
            }
        }
    }

    private fun validateUriClaims(payload: JSONObject) {
        listOf("aud", "nonce").forEach { field ->
            payload.optString(field, "").takeIf { it.isNotBlank() }
                ?.let { value ->
                    if (":" in value && !isValidUri(value)) {
                        throw ValidationException(ERROR_INVALID_URI + value, ERROR_CODE_INVALID)
                    }
                }
        }
    }

    private fun validateConfirmationClaim(payload: JSONObject) {
        payload.optJSONObject("cnf")?.let { cnf ->
            require(cnf.has("jwk") || cnf.has("kid")) {
                ValidationException("Invalid 'cnf' object: must contain either 'jwk' or 'kid'", ERROR_CODE_INVALID)
            }
        }
    }

    private fun validateSelectiveDisclosure(payload: JSONObject, disclosures: List<Disclosure>) {
        if (disclosures.isEmpty()) return

        require(payload.has("_sd")) {
            ValidationException("Missing required '_sd' claim when disclosures are present", ERROR_CODE_INVALID)
        }

        val sdAlg = payload.optString("_sd_alg", "sha-256")
        require(sdAlg in SUPPORTED_SD_HASH_ALGORITHMS) {
            ValidationException("Unsupported _sd_alg: $sdAlg. Allowed: $SUPPORTED_SD_HASH_ALGORITHMS", ERROR_CODE_INVALID)
        }

        val sdArray = payload.optJSONArray("_sd")
        require(sdArray != null && sdArray.length() == disclosures.size) {
            ValidationException(
                "Mismatch between number of disclosures (${disclosures.size}) and _sd entries (${sdArray?.length() ?: 0})",
                ERROR_CODE_INVALID
            )
        }

        validateDigests(sdArray, sdAlg)
    }

    private fun validateDigests(sdArray: JSONArray, sdAlg: String) {
        val expectedLength = HASH_LENGTHS[sdAlg.lowercase()]!!

        repeat(sdArray.length()) { i ->
            val digest = sdArray.optString(i)
            require(digest.isNotBlank()) {
                ValidationException("Invalid digest at _sd[$i]: must be a non-empty string", ERROR_CODE_INVALID)
            }

            try {
                val decoded = Base64Decoder().decodeFromBase64Url(digest)
                require(decoded.size == expectedLength) {
                    ValidationException(
                        "Invalid digest length at _sd[$i]: expected $expectedLength bytes, got ${decoded.size}",
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
                2 -> { /* Valid array disclosure */ }
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
        require(name != null && !name.startsWith("_")) {
            ValidationException(
                "$ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME at index $index",
                ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME
            )
        }
    }

    private fun validateDisclosureSha(node: Any?, digestToDisclosure: Map<String, Disclosure>, allSdDigests: MutableSet<String>): Any? {
        return when (node) {
            is Map<*, *> -> {
                val mutableNode = node.toMutableMap() as MutableMap<String, Any?>
                (mutableNode["_sd"] as? List<*>)?.forEach { digest ->
                    val digestStr = digest as? String ?: return@forEach
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
                    mutableNode[key] = processSdJwtPayload(value, digestToDisclosure, allSdDigests)
                }
                mutableNode
            }
            is List<*> -> {
                node.map { item ->
                    processSdJwtPayload(item, digestToDisclosure, allSdDigests)
                }
            }
            else -> {
                node
            }
        }
    }

    private fun validateKeyBindingJwt(kbJwt: String) {
        val parts = kbJwt.split(".")
        require(parts.size == 3) {
            ValidationException(ERROR_MESSAGE_INVALID_KB_JWT_FORMAT, ERROR_CODE_INVALID_KB_JWT_FORMAT)
        }

        val payload = JSONObject(decodeBase64Json(parts[1]))
        validateKeyBindingPayload(payload)
    }

    private fun validateKeyBindingPayload(payload: JSONObject) {
        val requiredFields = listOf("aud", "nonce", "cnf")

        requiredFields.forEach { field ->
            require(payload.has(field)) {
                ValidationException("Missing '$field' in Key Binding JWT", ERROR_CODE_INVALID)
            }
        }

        val aud = payload.optString("aud")
        require(aud.isNotBlank()) {
            ValidationException("'aud' in Key Binding JWT must be a non-empty string", ERROR_CODE_INVALID)
        }

        if (":" in aud) {
            require(isValidUri(aud)) {
                ValidationException("'aud' in Key Binding JWT must be a valid URI when containing ':'", ERROR_CODE_INVALID)
            }
        }

        val nonce = payload.optString("nonce")
        require(nonce.isNotBlank()) {
            ValidationException("'nonce' in Key Binding JWT must be a non-empty string", ERROR_CODE_INVALID)
        }

        val cnf = payload.optJSONObject("cnf")
        require(cnf != null && (cnf.has("jwk") || cnf.has("kid"))) {
            ValidationException("Invalid or missing 'cnf' in Key Binding JWT", ERROR_CODE_INVALID)
        }
    }

    private fun decodeBase64Json(encoded: String): String {
        val decodedBytes = Base64Decoder().decodeFromBase64Url(encoded)
        return String(decodedBytes)
    }
}