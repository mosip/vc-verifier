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
import io.mosip.vercred.vcverifier.Constants.ERROR_VALID_URI
import io.mosip.vercred.vcverifier.Constants.ERROR_VC_EXPIRED
import io.mosip.vercred.vcverifier.Constants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.Constants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.Constants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONObject

class CredentialsValidator {

    private val requiredFields = listOf(
        CREDENTIAL,
        "$CREDENTIAL.$ID",
        "$CREDENTIAL.$PROOF",
        "$CREDENTIAL.$ISSUER",
        "$CREDENTIAL.$CONTEXT",
        "$CREDENTIAL.$TYPE",
        "$CREDENTIAL.$CREDENTIAL_SUBJECT",
        "$CREDENTIAL.$ISSUANCE_DATE"
    )

    fun validateCredential(vcJsonString: String?): VerificationResult {

        try {
            if (vcJsonString.isNullOrEmpty()) {
                return VerificationResult(false, ERROR_EMPTY_VC_JSON)
            }

            val vcJsonObject = JSONObject(vcJsonString)

            val mandatoryCheck = checkMandatoryFields(vcJsonObject, requiredFields)
            if (!mandatoryCheck.verificationStatus) {
                return mandatoryCheck
            }

            val invalidCheck = checkInvalidFields(vcJsonObject)
            if (!invalidCheck.verificationStatus) {
                return invalidCheck
            }


            return handleExpiredVC(vcJsonObject)
        } catch (e: Exception){
            return  VerificationResult(false, "$EXCEPTION_DURING_VALIDATION${e.message.toString()}")
        }
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

        val firstContext = rootCredentialObject.getJSONArray(CONTEXT).getString(0)
        if (firstContext != CREDENTIALS_CONTEXT_V1_URL) {
            return VerificationResult(false, ERROR_CONTEXT_FIRST_LINE)
        }

        val issuer = rootCredentialObject.optString(ISSUER)
        if (!Util().isValidUri(issuer)) {
            return VerificationResult(false, "$CREDENTIAL.$ISSUER$ERROR_VALID_URI")
        }

        listOf(ISSUANCE_DATE to ERROR_ISSUANCE_DATE_INVALID,
            EXPIRATION_DATE to ERROR_EXPIRATION_DATE_INVALID).forEach { (dateKey, errorMessage) ->
            if (rootCredentialObject.has(dateKey) && !Util().isValidDate(rootCredentialObject.get(dateKey).toString())) {
                return VerificationResult(false, errorMessage)
            }
        }

        rootCredentialObject.optJSONArray(TYPE)?.let { types ->
            if (!Util().jsonArrayToList(types).contains(VERIFIABLE_CREDENTIAL)) {
                return VerificationResult(false, ERROR_TYPE_VERIFIABLE_CREDENTIAL)
            }
        }

        return VerificationResult(true)
    }

    private fun handleExpiredVC(vcJsonObject: JSONObject): VerificationResult{
        val expirationDate = vcJsonObject.getJSONObject(CREDENTIAL).get(EXPIRATION_DATE).toString()
        if(Util().isDateExpired(expirationDate)){
            return VerificationResult(true, ERROR_VC_EXPIRED)
        }
        return VerificationResult(true)
    }

    companion object{
        const val CREDENTIALS_CONTEXT_V1_URL = "https://www.w3.org/2018/credentials/v1"
        const val VERIFIABLE_CREDENTIAL = "VerifiableCredential"
    }

}

data class VerificationResult(
    val verificationStatus: Boolean,
    val verificationErrorMessage: String = ""

)

