package io.mosip.vercred.vcverifier.utils

import android.os.Build
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.unmockkStatic
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test


class Base64DecoderTest {
    @BeforeEach
    fun setUp() {
        mockkObject(Util.Companion)
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
            val base64Decoder = Base64Decoder()

            val decodedContent = base64Decoder.decodeFromBase64UrlFormatEncoded("aGVsbG8gd29ybGQ=")

            assertEquals("hello world", decodedContent.toString(Charsets.UTF_8))
        }

        @Test
        fun `should throw error when given base64 url encoded data contains non base64 character`() {
            val base64Decoder = Base64Decoder()

            val exception = assertThrows(IllegalArgumentException::class.java) {
                base64Decoder.decodeFromBase64UrlFormatEncoded("aGVsbG8%d29ybGQ=")
            }

            assertEquals(
                "Illegal base64 character 25",
                exception.message
            )
        }

        @Test
        fun `should throw error when given base64 url encoded data has truncated bytes`() {
            val base64Decoder = Base64Decoder()

            val exception = assertThrows(IllegalArgumentException::class.java) {
                base64Decoder.decodeFromBase64UrlFormatEncoded("aGVsbG8gd29ybG=")
            }

            assertEquals(
                "Input byte array has wrong 4-byte ending unit",
                exception.message
            )
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
            val base64Decoder = Base64Decoder()

            val decodedData: ByteArray = base64Decoder.decodeFromBase64UrlFormatEncoded("aGVsbG8gd29ybGQ")

            assertTrue("hello world".toByteArray().contentEquals(decodedData))
        }

        @Test
        fun `should decode the base64 url encoded content successfully with API lesser than  Version O`() {
            every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.N
            every {
                android.util.Base64.decode(
                    "aGVsbG8gd29ybGQ=",
                    android.util.Base64.DEFAULT
                )
            } returns "hello world".toByteArray()
            val base64Decoder = Base64Decoder()

            val decodedData: ByteArray = base64Decoder.decodeFromBase64UrlFormatEncoded("aGVsbG8gd29ybGQ")

            assertEquals("hello world", decodedData.toString(Charsets.UTF_8))
        }
    }
}