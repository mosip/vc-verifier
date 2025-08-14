package io.mosip.vercred.vcverifier.utils

import android.os.Build
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.unmockkStatic
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test


class Base64EncoderTest {
    @BeforeEach
    fun setUp() {
        mockkObject(Util)
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Nested
    inner class JavaEnvironment {
        @BeforeEach
        fun setUp() {
            every { Util.isAndroid() } returns false
        }

        @Test
        fun `should decode the base64 url encoded content successfully`() {
            val base64Encoder = Base64Encoder()
            val encodedData = base64Encoder.encodeToBase64Url("hello world".toByteArray())
            assertEquals("aGVsbG8gd29ybGQ", encodedData)
        }

        @Test
        fun `should handle empty byte array properly`() {
            val base64Encoder = Base64Encoder()
            val encodedData = base64Encoder.encodeToBase64Url(ByteArray(0))
            assertEquals("", encodedData)
        }

        @Test
        fun `should handle special characters correctly during encoding`() {
            val base64Encoder = Base64Encoder()
            val specialChars = "!@#$%^&*()_+{}[]|\":<>?,./"
            val encodedContent = base64Encoder.encodeToBase64Url(specialChars.toByteArray())
            val decodedContent = Base64Decoder().decodeFromBase64Url(encodedContent)
            assertEquals(specialChars, decodedContent.toString(Charsets.UTF_8))
        }

    }


    @Nested
    inner class AndroidEnvironment {
        @BeforeEach
        fun setUp() {
            every { Util.isAndroid() } returns true

            mockkObject(BuildConfig)

            mockkStatic(android.util.Base64::class)

        }

        @AfterEach
        fun tearDown() {
            unmockkStatic(android.util.Base64::class)
        }

        @Test
        fun `should decode the base64 url encoded content successfully with API greater than or equal to Version O`() {
            every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
            val base64Encoder = Base64Encoder()
            val encodedData = base64Encoder.encodeToBase64Url("hello world".toByteArray())
            assertEquals("aGVsbG8gd29ybGQ", encodedData)
        }

    }
}