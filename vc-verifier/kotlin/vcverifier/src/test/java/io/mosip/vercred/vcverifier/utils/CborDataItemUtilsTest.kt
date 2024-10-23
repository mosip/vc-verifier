package io.mosip.vercred.vcverifier.utils

import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class CborDataItemUtilsTest {
    @Test
    fun `should convert to dataItem from ByteArray`() {
        val byteArray: ByteArray = CborDataItemUtils.toByteArray(UnicodeString("23"))

        assertEquals("b23",String(byteArray,Charsets.UTF_8))
    }

    @Test
    fun `should convert to byteArray from DataItem`() {
        val datItem = CborDataItemUtils.fromByteArray(byteArrayOf(2))

        assertEquals(UnsignedInteger(2),datItem)
    }
}