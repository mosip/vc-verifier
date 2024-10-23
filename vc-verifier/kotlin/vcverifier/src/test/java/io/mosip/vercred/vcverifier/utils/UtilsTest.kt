package io.mosip.vercred.vcverifier.utils

import android.util.Log
import io.mockk.InternalPlatformDsl.toArray
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkStatic
import org.json.JSONArray
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream


class UtilsTest {
    @BeforeEach
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0
    }

    @AfterEach
    fun after() {
        clearAllMocks()
    }

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
        val result = dateUtils.isDatePassedCurrentDate("2024-11-02T17:36:13.644Z")
        assertFalse(result)
    }

    @Test
    fun `invalid date`() {
        val result = dateUtils.isDatePassedCurrentDate("12345")
        assertFalse(result)
    }

    @Test
    fun `test if date1 is greater than date2`() {
        val date1 = "2026-10-23T07:01:17Z"
        val date2 = "2024-10-23T07:01:17Z"

        val isDate1GreaterThanDate2 = dateUtils.isDate1GreaterThanDate2(date1, date2)

        assertTrue(isDate1GreaterThanDate2)
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
}