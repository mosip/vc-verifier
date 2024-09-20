package io.mosip.vercred.vcverifier.utils

class Util {
    val isAndroid: Boolean
        get() = System.getProperty("java.vm.name")?.contains("Dalvik") == true
}