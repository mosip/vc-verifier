package io.mosip.vercred.vcverifier.utils

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.model.Map
import java.io.ByteArrayInputStream
import kotlin.Any
import kotlin.Array
import kotlin.Boolean
import kotlin.ByteArray
import kotlin.IllegalArgumentException
import kotlin.Int
import kotlin.Long
import kotlin.String


class CBORConverter {

    companion object {
        fun toDataItem(value: Any): DataItem {
            return when (value) {
                is DataItem -> value
                is String -> UnicodeString(value)
                is Int -> UnsignedInteger(value.toLong())
                is Long -> UnsignedInteger(value)
                is Boolean -> {
                    if (value) SimpleValue.TRUE else SimpleValue.FALSE
                }

                is kotlin.collections.Map<*, *> -> {
                    val cborMap = Map()
                    value.forEach { (key, value) ->
                        cborMap.put(UnicodeString(key as String), toDataItem(value!!))
                    }
                    cborMap
                }

                is List<*> -> {
                    val cborArray = Array()
                    value.forEach { item ->
                        cborArray.add(toDataItem(item!!))
                    }
                    cborArray
                }

                is Array<*> -> {
                    val cborArray = Array()
                    value.forEach { item ->
                        cborArray.add(toDataItem(item!!))
                    }
                    cborArray
                }

                is ByteArray -> {
                    val byteArrayInputStream = ByteArrayInputStream(value)
                    val dataItems = CborDecoder(byteArrayInputStream).decode()
                    return dataItems.firstOrNull()!!
                }

                else -> throw IllegalArgumentException("Unsupported value: $value ${value.javaClass.simpleName}")
            }
        }


    }
}


