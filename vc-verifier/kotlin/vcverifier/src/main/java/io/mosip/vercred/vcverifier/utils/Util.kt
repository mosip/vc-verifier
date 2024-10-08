package io.mosip.vercred.vcverifier.utils

import io.mosip.vercred.vcverifier.Constants.DATE_REGEX
import java.net.URI

class Util {
    val isAndroid: Boolean
        get() = System.getProperty("java.vm.name")?.contains("Dalvik") == true


    fun isValidUri(value: String): Boolean {
        return try {
            val uri = URI(value)
            (uri.scheme != null && uri.host != null)
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

}