package io.mosip.vercred.vcverifier.utils

import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.DATE_REGEX
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EXPIRATION_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ISSUANCE_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_FROM
import io.mosip.vercred.vcverifier.data.VerificationResult
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale

class DateUtils {
    fun isValidDate(dateValue: String): Boolean {
        return DATE_REGEX.matches(dateValue)
    }

    fun isDatePassedCurrentDate(inputDateString: String): Boolean {
        return try {
            val format = SimpleDateFormat(COMMON_DATE_FORMAT, Locale.getDefault())
            val inputDate = format.parse(inputDateString)
            val currentDate = Calendar.getInstance().time
            inputDate.before(currentDate)
        } catch (e: Exception) {
            false
        }
    }

    fun validateV1DateFields(vcJsonObject: JSONObject): VerificationResult {
        val validationResult = listOf(
            ISSUANCE_DATE to ERROR_ISSUANCE_DATE_INVALID,
            EXPIRATION_DATE to ERROR_EXPIRATION_DATE_INVALID
        ).mapNotNull { (dateKey, errorMessage) ->
            if (vcJsonObject.has(dateKey) && !isValidDate(vcJsonObject.get(dateKey).toString())) {
                VerificationResult(false, errorMessage)
            } else {
                null
            }
        }.firstOrNull() ?: VerificationResult(true)

        if (!validationResult.verificationStatus) {
            return validationResult
        }

        if (!isDatePassedCurrentDate(vcJsonObject.optString(ISSUANCE_DATE))) {
            return VerificationResult(false, ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE)
        }

        return VerificationResult(true)
    }

    fun validateV2DateFields(vcJsonObject: JSONObject): VerificationResult {

        if (vcJsonObject.has(VALID_FROM) && !isDatePassedCurrentDate(vcJsonObject.optString(
                VALID_FROM
            ))) {
            return VerificationResult(false, ERROR_CURRENT_DATE_BEFORE_VALID_FROM)
        }

        return VerificationResult(true)
    }

    fun isVCExpired(inputDate: String): Boolean {
        return inputDate.isNotEmpty() && DateUtils().isDatePassedCurrentDate(inputDate)
    }

    companion object{
        const val COMMON_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
    }
}