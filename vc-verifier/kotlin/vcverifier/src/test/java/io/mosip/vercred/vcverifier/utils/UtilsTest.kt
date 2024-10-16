package io.mosip.vercred.vcverifier.utils

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Test


class UtilsTest {

    private val utils = Util()
    private val dateUtils = DateUtils()

    @Test
    fun `test validate date invalid`() {
        val result = dateUtils.isValidDate("123456789")
        assertEquals(false, result)
    }

    @Test
    fun `test validate date valid`() {
        val result = dateUtils.isValidDate("2024-09-02T17:36:13.644Z")
        assertEquals(true, result)
    }

    @Test
    fun `test validate uri invalid`() {
        val result = utils.isValidUri("invalid_uri")
        assertEquals(false, result)
    }

    @Test
    fun `test validate uri valid`() {
        val result = utils.isValidUri("http://www.google.com")
        assertEquals(true, result)
    }

    @Test
    fun `test validate uri valid did`() {
        val result = utils.isValidUri("did:jwk:eysdsdsd")
        assertEquals(true, result)
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
    fun `date expired`(){
        val result = dateUtils.isVCExpired("2024-09-02T17:36:13.644Z")
        assertEquals(true, result)
    }

    @Test
    fun `date not expired`(){
        val result = dateUtils.isDatePassedCurrentDate("2024-11-02T17:36:13.644Z")
        assertEquals(false, result)
    }

    @Test
    fun `invalid date`(){
        val result = dateUtils.isDatePassedCurrentDate("12345")
        assertEquals(false, result)
    }
}