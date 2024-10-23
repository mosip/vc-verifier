package io.mosip.vercred.vcverifier.utils

import android.annotation.SuppressLint
import android.os.Build
import java.util.Base64

class Encoder {
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
}