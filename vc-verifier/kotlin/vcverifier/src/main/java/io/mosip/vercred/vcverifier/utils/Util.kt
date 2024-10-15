package io.mosip.vercred.vcverifier.utils

import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.DATE_REGEX
import java.net.URI
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale


class Util {

    fun isValidUri(value: String): Boolean {
        return try {
            val uri = URI(value)
            (uri.scheme=="did") || (uri.scheme != null && uri.host != null)
        } catch (e: Exception) {
            false
        }
    }

    fun isValidDate(dateValue: String): Boolean {
        return DATE_REGEX.matches(dateValue)
    }

    fun jsonArrayToList(jsonArray: org.json.JSONArray): List<Any> {
        return List(jsonArray.length()) { jsonArray.get(it) }
    }

    fun isDateExpired(inputDateString: String): Boolean {
        return try {
            val format = SimpleDateFormat(COMMON_DATE_FORMAT, Locale.getDefault())
            val inputDate = format.parse(inputDateString)
            val currentDate = Calendar.getInstance().time
            inputDate.before(currentDate)
        } catch (e: Exception) {
            false
        }
    }

    companion object{
        const val COMMON_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
    }

}