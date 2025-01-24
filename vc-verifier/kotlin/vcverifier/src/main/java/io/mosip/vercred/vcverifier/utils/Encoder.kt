package io.mosip.vercred.vcverifier.utils

import android.annotation.SuppressLint
import android.os.Build
import java.util.Base64

class Encoder {
    fun decodeFromBase64UrlFormatEncoded(content: String): ByteArray {
        return if (Util().isAndroid()) {
            if( BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O){
                javaBase64UrlDecode(content)
            } else {
                androidBase64UrlDecode(content)
            }
        } else {
            javaBase64UrlDecode(content)
        }
    }

    @SuppressLint("NewApi")
    private fun javaBase64UrlDecode(content: String): ByteArray =
        Base64.getUrlDecoder().decode(content.toByteArray())

    private fun androidBase64UrlDecode(content: String): ByteArray {
        var base64: String = content.replace('-', '+').replace('_', '/')
        when (base64.length % 4) {
            2 -> base64 += "=="
            3 -> base64 += "="
            else -> {}
        }

        return android.util.Base64.decode(base64, android.util.Base64.DEFAULT)
    }
}