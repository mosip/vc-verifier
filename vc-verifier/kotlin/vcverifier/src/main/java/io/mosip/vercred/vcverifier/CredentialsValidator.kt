package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.Constants.CREDENTIAL
import io.mosip.vercred.vcverifier.Constants.ID
import io.mosip.vercred.vcverifier.Constants.PROOF
import io.mosip.vercred.vcverifier.Constants.ISSUER
import io.mosip.vercred.vcverifier.Constants.CONTEXT
import io.mosip.vercred.vcverifier.Constants.TYPE
import io.mosip.vercred.vcverifier.Constants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.Constants.ERROR_CONTEXT_FIRST_LINE
import io.mosip.vercred.vcverifier.Constants.ERROR_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.Constants.ERROR_EXPIRATION_DATE_INVALID
import io.mosip.vercred.vcverifier.Constants.ERROR_ISSUANCE_DATE_INVALID
import io.mosip.vercred.vcverifier.Constants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.Constants.ERROR_TYPE_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.Constants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.Constants.EXPIRATION_DATE
import org.json.JSONObject
import java.net.URI

class CredentialsValidator {

    private val requiredFields = listOf(
        CREDENTIAL,
        "$CREDENTIAL.$ID",
        "$CREDENTIAL.$PROOF",
        "$CREDENTIAL.$ISSUER",
        "$CREDENTIAL.$CONTEXT",
        "$CREDENTIAL.$TYPE",
        "$CREDENTIAL.$CREDENTIAL_SUBJECT",
        "$CREDENTIAL.$ISSUANCE_DATE",
        "$CREDENTIAL.$EXPIRATION_DATE"
    )

    fun validateCredential(vcJsonString: String?): VerificationResult {

        if (vcJsonString.isNullOrEmpty()) {
            return VerificationResult(false, ERROR_EMPTY_VC_JSON)
        }

        val vcJsonObject = JSONObject(vcJsonString)

        val mandatoryCheck = checkMandatoryFields(vcJsonObject, requiredFields)
        if (!mandatoryCheck.verificationStatus) {
            return mandatoryCheck
        }

        return checkInvalidFields(vcJsonObject)
    }

    private fun checkMandatoryFields(vcJsonObject: JSONObject, fields: List<String>): VerificationResult {

        for (field in fields) {
            val keys = field.split(".")
            var currentJson: JSONObject? = vcJsonObject

            for (key in keys) {
                if (currentJson != null && currentJson.has(key)) {
                    if (currentJson.get(key) is JSONObject) {
                        currentJson = currentJson.getJSONObject(key)
                    } else {
                        break
                    }
                } else {
                    return VerificationResult(false, "$ERROR_MISSING_REQUIRED_FIELDS$field")
                }
            }
        }

        return VerificationResult(true)
    }

    private fun checkInvalidFields(vcJsonObject: JSONObject): VerificationResult {
        val rootCredentialObject = vcJsonObject.getJSONObject(CREDENTIAL)
        val credentialSubject = rootCredentialObject.getJSONObject(CREDENTIAL_SUBJECT)

        val firstContext = rootCredentialObject.getJSONArray(CONTEXT).getString(0)
        if (firstContext != CREDENTIALS_CONTEXT_V1_URL) {
            return VerificationResult(false, ERROR_CONTEXT_FIRST_LINE)
        }

        if (credentialSubject.has(ID) && credentialSubject.get(ID).toString().isNotEmpty()) {
            validateUriId(credentialSubject.get(ID).toString(), "$CREDENTIAL.$ID")
        }

        if (rootCredentialObject.has(ISSUANCE_DATE) && !isValidDate(rootCredentialObject.get(
                ISSUANCE_DATE).toString())) {
            return VerificationResult(false, ERROR_ISSUANCE_DATE_INVALID)
        }

        if (rootCredentialObject.has(EXPIRATION_DATE) && !isValidDate(rootCredentialObject.get(
                EXPIRATION_DATE).toString())) {
            return VerificationResult(false, ERROR_EXPIRATION_DATE_INVALID)
        }

        if (rootCredentialObject.has(TYPE)) {
            val types = rootCredentialObject.optJSONArray(TYPE)

            if (types == null || !jsonArrayToList(types).map { it.toString() }.contains(VERIFIABLE_CREDENTIAL)) {
                return VerificationResult(false, ERROR_TYPE_VERIFIABLE_CREDENTIAL)
            }
        }

        return VerificationResult(true)
    }


    fun validateUriId(id: String, propertyName: String) {
        try {
            URI(id)
        } catch (e: Exception) {
            throw IllegalArgumentException("\"$propertyName\" must be a URI: \"$id\".", e)
        }
    }

    fun isValidDate(dateValue: String): Boolean {
        return DATE_REGEX.matches(dateValue)
    }

    companion object{
        const val CREDENTIALS_CONTEXT_V1_URL = "https://www.w3.org/2018/credentials/v1"
         val DATE_REGEX = Regex(
            """^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(Z|(\+|-)([01][0-9]|2[0-3]):([0-5][0-9]))$""",
            RegexOption.IGNORE_CASE
        )
        const val VERIFIABLE_CREDENTIAL = "VerifiableCredential"


    }
    private fun jsonArrayToList(jsonArray: org.json.JSONArray): List<Any> {
        return List(jsonArray.length()) { jsonArray.get(it) }
    }

}

data class VerificationResult(
    val verificationStatus: Boolean,
    val verificationErrorMessage: String = ""

)

