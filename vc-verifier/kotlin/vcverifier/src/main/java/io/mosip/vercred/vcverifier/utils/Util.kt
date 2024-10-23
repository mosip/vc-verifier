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
            (uri.scheme == "did") || (uri.scheme != null && uri.host != null)
        } catch (e: Exception) {
            false
        }
    }

    fun jsonArrayToList(jsonArray: org.json.JSONArray): List<Any> {
        return List(jsonArray.length()) { jsonArray.get(it) }
    }

    fun getContextVersion(vcJsonObject: JSONObject): DATA_MODEL? {
        if (vcJsonObject.has(CONTEXT)) {
            val contextUrl = vcJsonObject.getJSONArray(CONTEXT).get(0)
            return when (contextUrl) {
                CREDENTIALS_CONTEXT_V1_URL -> DATA_MODEL.DATA_MODEL_1_1
                CREDENTIALS_CONTEXT_V2_URL -> DATA_MODEL.DATA_MODEL_2_0
                else -> DATA_MODEL.UNSUPPORTED
            }
        }
        return null
    }

    @SuppressLint("NewApi")
    fun decodeFromBase64UrlFormatEncoded(content: String): ByteArray {
        return if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            Base64.getUrlDecoder().decode(content.toByteArray())
        } else {
            var base64: String = content.replace('-', '+').replace('_', '/')
            when (base64.length % 4) {
                2 -> base64 += "=="
                3 -> base64 += "="
                else -> {}
            }

            return android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
        }
    }

    fun calculateDigest(
        algorithm: String,
        data: ByteArrayOutputStream,
    ): ByteArray =
        MessageDigest.getInstance(algorithm).digest(data.toByteArray())
}
