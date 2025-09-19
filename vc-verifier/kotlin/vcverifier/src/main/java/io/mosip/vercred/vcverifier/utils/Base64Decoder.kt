package io.mosip.vercred.vcverifier.utils

import android.annotation.SuppressLint
import android.os.Build
import java.util.Base64

class Base64Decoder {
    fun decodeFromBase64Url(content: String): ByteArray {
        return if (Util.isAndroid()) {
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
        val base64: String = content.replace('-', '+').replace('_', '/')
        val paddedBase64 = when (base64.length % 4) {
            2 -> base64 + "=="
            3 -> base64 + "="
            else -> base64
        }

        return android.util.Base64.decode(paddedBase64, android.util.Base64.DEFAULT)
    }

    fun decodeFromBase64(content: String): ByteArray {
        return if (Util.isAndroid()) {
            if( BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O){
                javaBase64Decode(content)
            } else {
                android.util.Base64.decode(content, android.util.Base64.DEFAULT)
            }
        } else {
            javaBase64Decode(content)
        }
    }

    @SuppressLint("NewApi")
    private fun javaBase64Decode(content: String): ByteArray =
        Base64.getDecoder().decode(content.toByteArray())

}