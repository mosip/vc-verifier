package io.mosip.vercred.vcverifier.utils

import android.annotation.SuppressLint
import android.os.Build
import java.util.Base64

class Base64Encoder {
    fun encodeToBase64UrlFormatEncoded(content: ByteArray): String {
        return if (Util.isAndroid()) {
            if( BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O){
                javaBase64UrlDecode(content)
            } else {
                androidBase64UrlEncode(content)
            }
        } else {
            javaBase64UrlDecode(content)
        }
    }

    @SuppressLint("NewApi")
    private fun javaBase64UrlDecode(content: ByteArray): String =
        String(Base64.getUrlEncoder().withoutPadding().encode(content))

    private fun androidBase64UrlEncode(content: ByteArray): String {
        val base64 = String(android.util.Base64.encode(content, android.util.Base64.DEFAULT))
        base64.replace('+', '-').replace('/', '_')
        return base64
    }
}