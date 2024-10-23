package io.mosip.vercred.vcverifier.utils

import android.util.Log
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.DATE_REGEX
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EXPIRATION_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ISSUANCE_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VALID_FROM_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VALID_UNTIL_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_UNTIL
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object DateUtils {

    private val dateFormats = listOf(
        ("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
        ("yyyy-MM-dd'T'HH:mm:ss'Z'")
    )

    private const val UTC = "UTC"

    fun isValidDate(dateValue: String): Boolean {
        return DATE_REGEX.matches(dateValue)
    }

    fun isDatePassedCurrentDate(inputDateString: String): Boolean {
        return try {
            val inputDate: Date? = parseDate(inputDateString)
            if (inputDate == null) {
                Log.e("VC-VERIFIER", "Given date is not available in supported date formats")
                return false
            }

            val currentDate = Calendar.getInstance(TimeZone.getTimeZone(UTC)).time
            inputDate.before(currentDate)
        } catch (e: Exception) {
            Log.e("VC-VERIFIER", "Error while comparing dates ${e.message}")
            false
        }
    }

    fun parseDate(date: String): Date? {
        dateFormats.forEach {
            try {
                val format = SimpleDateFormat(it, Locale.getDefault()).apply {
                    timeZone = TimeZone.getTimeZone(UTC)
                }
                return format.parse(date)
            } catch (_: Exception) {
            }
        }
        return null
    }

    fun validateV1DateFields(vcJsonObject: JSONObject) {
        listOf(
            ISSUANCE_DATE to ERROR_ISSUANCE_DATE_INVALID,
            EXPIRATION_DATE to ERROR_EXPIRATION_DATE_INVALID
        ).map { (dateKey, errorMessage) ->
            if (vcJsonObject.has(dateKey) && !isValidDate(vcJsonObject.get(dateKey).toString())) {
                throw ValidationException(errorMessage)
            }
        }


        if (!isDatePassedCurrentDate(vcJsonObject.optString(ISSUANCE_DATE))) {
            throw ValidationException(ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE)
        }

    }

    fun validateV2DateFields(vcJsonObject: JSONObject) {

        listOf(
            VALID_FROM to ERROR_VALID_FROM_INVALID,
            VALID_UNTIL to ERROR_VALID_UNTIL_INVALID
        ).map { (dateKey, errorMessage) ->
            if (vcJsonObject.has(dateKey) && !isValidDate(vcJsonObject.get(dateKey).toString())) {
                throw ValidationException(errorMessage)
            }
        }

        if (vcJsonObject.has(VALID_FROM) && !isDatePassedCurrentDate(
                vcJsonObject.optString(
                    VALID_FROM
                )
            )
        ) {
            throw ValidationException(ERROR_CURRENT_DATE_BEFORE_VALID_FROM)
        }
    }

    fun isVCExpired(inputDate: String): Boolean {
        return inputDate.isNotEmpty() && isDatePassedCurrentDate(inputDate)
    }

}