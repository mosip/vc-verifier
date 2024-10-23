package io.mosip.vercred.vcverifier.utils

import android.os.Build
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test


class EncoderTest {
    @BeforeEach
    fun setUp() {
        mockkObject(BuildConfig)
    }

    @Test
    fun `should encode the given string to base64 url formal with API greater than or equal to Version O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
        val encoder = Encoder()

        val decodedData: ByteArray = encoder.decodeFromBase64UrlFormatEncoded("aGVsbG8gd29ybGQ=")

        assertTrue("hello world".toByteArray().contentEquals(decodedData))
    }

    @Test
    fun `should decode the given byteArray from base64 url formal with API lesser than  Version O`() {
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.N
        mockkStatic(android.util.Base64::class)
        every { android.util.Base64.decode(any<String>(), android.util.Base64.DEFAULT) } returns "hello world".toByteArray()
        val encoder = Encoder()

        val decodedData: ByteArray = encoder.decodeFromBase64UrlFormatEncoded("aGVsbG8gd29ybGQ=")

        assertEquals("hello world", decodedData.toString(Charsets.UTF_8))
    }
}