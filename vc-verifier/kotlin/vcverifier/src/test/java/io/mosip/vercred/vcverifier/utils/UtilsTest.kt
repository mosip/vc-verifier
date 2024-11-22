package io.mosip.vercred.vcverifier.utils

import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import org.json.JSONArray
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.Calendar
import java.util.Date


class UtilsTest {

    private val utils = Util()
    private val dateUtils = DateUtils

    @Test
    fun `test validate date invalid`() {
        val result = dateUtils.isValidDate("123456789")
        assertFalse(result)
    }

    @Test
    fun `test validate date valid`() {
        val result = dateUtils.isValidDate("2024-09-02T17:36:13.644Z")
        assertTrue(result)
    }

    @Test
    fun `test validate uri invalid`() {
        val result = utils.isValidUri("invalid_uri")
        assertFalse(result)
    }

    @Test
    fun `test validate uri valid`() {
        val result = utils.isValidUri("http://www.google.com")
        assertTrue(result)
    }

    @Test
    fun `test validate uri valid did`() {
        val result = utils.isValidUri("did:jwk:eysdsdsd")
        assertTrue(result)
    }

    @Test
    fun `test empty JSONArray`() {
        val jsonArray = JSONArray()
        val result = utils.jsonArrayToList(jsonArray)
        assertEquals(emptyList<Any>(), result)
    }

    @Test
    fun `test JSONArray with strings`() {
        val jsonArray = JSONArray()
        jsonArray.put("element1")
        jsonArray.put("element2")
        jsonArray.put("element3")

        val result = utils.jsonArrayToList(jsonArray)
        assertEquals(listOf("element1", "element2", "element3"), result)
    }

    @Test
    fun `date expired`() {
        val result = dateUtils.isVCExpired("2024-09-02T17:36:13.644Z")
        assertTrue(result)
    }

    @Test
    fun `date not expired`() {
        val calendar: Calendar = mockk(relaxed = true)
        mockkStatic(Calendar::class)
        every { Calendar.getInstance() } returns calendar
        val result = dateUtils.isDatePassedCurrentDate("2024-11-02T17:36:13.644Z")
        assertFalse(result)
    }

    @Test
    fun `invalid date`() {
        val result = dateUtils.isDatePassedCurrentDate("12345")
        assertFalse(result)
    }

    @Test
    fun `test calculation of message digest`() {
        val byteArrayOutputStream = ByteArrayOutputStream()
        byteArrayOutputStream.write("hello".toByteArray())


        val digest: ByteArray = Util().calculateDigest("SHA-256", byteArrayOutputStream)

        assertArrayEquals(
            byteArrayOf(
                44,
                -14,
                77,
                -70,
                95,
                -80,
                -93,
                14,
                38,
                -24,
                59,
                42,
                -59,
                -71,
                -30,
                -98,
                27,
                22,
                30,
                92,
                31,
                -89,
                66,
                94,
                115,
                4,
                51,
                98,
                -109,
                -117,
                -104,
                36
            ), (digest)
        )
    }

    @Test
    fun `test when issuanceDate time is not future date and 10 seconds less than currentDate time `() {
        val currentDate = Date()
        val issuanceDate = Date(currentDate.time-10000)
        val result = issuanceDate.isFutureDateWithTolerance()
        assertFalse(result)
    }

    @Test
    fun `test when issuanceDate time is not future date and 3 seconds less than currentDate time `() {
        val currentDate = Date()
        val issuanceDate = Date(currentDate.time-3000)
        val result = issuanceDate.isFutureDateWithTolerance()
        assertFalse(result)
    }

    @Test
    fun `test when issuanceDate time equal to future date time`() {
        val issuanceDate = Date()
        val result = issuanceDate.isFutureDateWithTolerance()
        assertFalse(result)
    }


    @Test
    fun `test when issuanceDate time is future date time but within tolerance range`() {
        val currentDate = Date()
        val issuanceDate = Date(currentDate.time+3000)

        val result = issuanceDate.isFutureDateWithTolerance()
        assertFalse(result)
    }

    @Test
    fun `test when issuanceDate time is future date time but outside tolerance range`() {
        val currentDate = Date()
        val issuanceDate = Date(currentDate.time+5000)

        val result = issuanceDate.isFutureDateWithTolerance()
        assertTrue(result)
    }
}