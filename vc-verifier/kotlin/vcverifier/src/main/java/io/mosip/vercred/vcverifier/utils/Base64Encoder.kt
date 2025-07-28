package io.mosip.vercred.vcverifier.utils


import android.annotation.SuppressLint
import android.os.Build
import android.util.Base64.*
import java.util.Base64.*

class Base64Encoder {
    fun encodeToBase64Url(data: ByteArray): String {
        return if (Util.isAndroid()) {
            if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
                javaBase64UrlEncode(data)
            } else {
                androidBase64UrlEncode(data)
            }
        } else {
            javaBase64UrlEncode(data)
        }
    }

    @SuppressLint("NewApi")
    private fun javaBase64UrlEncode(data: ByteArray): String =
        getUrlEncoder().withoutPadding().encodeToString(data)

    private fun androidBase64UrlEncode(data: ByteArray): String {
        val base64 = encodeToString(data, NO_PADDING)
        return base64
    }
}

