package io.mosip.vercred.vcverifier.utils

import android.os.Build

object BuildConfig {
    fun getVersionSDKInt(): Int {
        return Build.VERSION.SDK_INT
    }
}