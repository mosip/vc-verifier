package io.mosip.vercred.vcverifier.utils

import android.annotation.SuppressLint
import android.os.Build
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIALS_CONTEXT_V1_URL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIALS_CONTEXT_V2_URL
import io.mosip.vercred.vcverifier.data.DATA_MODEL
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.URI
import java.security.MessageDigest
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeParseException
import java.util.Base64


class Util {

    fun getId(obj: Any): String? {
        return when (obj) {
            is String -> obj
            is Map<*, *> -> obj["id"] as? String
            else -> null
        }
    }

    fun isValidUri(value: String): Boolean {

        return try {
            val uri = URI(value)
            (uri.scheme=="did") || (uri.scheme != null && uri.host != null)
        } catch (e: Exception) {
            false
        }
    }

    fun jsonArrayToList(jsonArray: org.json.JSONArray): List<Any> {
        return List(jsonArray.length()) { jsonArray.get(it) }
    }

    fun getContextVersion(vcJsonObject: JSONObject): DATA_MODEL?{
        if(vcJsonObject.has(CONTEXT)){
            val contextUrl = vcJsonObject.getJSONArray(CONTEXT).get(0)
            return when(contextUrl){
                CREDENTIALS_CONTEXT_V1_URL -> DATA_MODEL.DATA_MODEL_1_1
                CREDENTIALS_CONTEXT_V2_URL -> DATA_MODEL.DATA_MODEL_2_0
                else -> DATA_MODEL.UNSUPPORTED
            }
        }
        return null
    }

    val isAndroid: Boolean
        get() = System.getProperty("java.vm.name")?.contains("Dalvik") == true


    @SuppressLint("NewApi")
    fun decodeFromBase64UrlFormatEncoded(content: String): ByteArray {
        return if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            Base64.getUrlDecoder().decode(content.toByteArray())
        } else {
            TODO("VERSION.SDK_INT < O")
        }
    }

    @SuppressLint("NewApi")
    fun decodeFromBase64FormatEncoded(content: String): ByteArray {
        return if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            Base64.getDecoder().decode(content.toByteArray())
        } else {
            TODO("VERSION.SDK_INT < O")
        }
    }

    @SuppressLint("NewApi")
    fun isTimestamp(text: String?): Boolean {
        if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            try {
                // Try to parse as a timestamp (e.g., "2024-10-03T10:15:30")
                Instant.parse(text)
                return true
            } catch (e: DateTimeParseException) {
                println(e.message)
                return false
            }
        } else return false
    }

    @SuppressLint("NewApi")
    fun convertLocalDateTimeStringToInstant(dateStr: String): Instant {
        return if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            val localDate = LocalDate.parse(dateStr)
            localDate.atStartOfDay(ZoneOffset.UTC).toInstant()
        } else {
            TODO("VERSION.SDK_INT < O")
        }
    }

     fun calculateDigest(
         algorithm: String,
         data: ByteArrayOutputStream,
    ): ByteArray =
        MessageDigest.getInstance(algorithm).digest(data.toByteArray())
}
