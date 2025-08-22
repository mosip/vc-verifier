package io.mosip.vercred.vcverifier.keyResolver.types.http

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_HEX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_JWK
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_PEM
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class HttpsPublicKeyResolverTest {
    private val resolver = HttpsPublicKeyResolver()

    @BeforeEach
    fun setUp() {
        mockkObject(NetworkManagerClient.Companion)
    }

    @AfterEach
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }

    @Test
    fun `should throw exception for PEM public key`() {
        
        val uri = ("https://mock-server.com/pem")
        val mockResponse = mapOf(
            PUBLIC_KEY_PEM to "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=\n-----END PUBLIC KEY-----",
            KEY_TYPE to ED25519_KEY_TYPE_2020
        )
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns mockResponse

        val publicKey = resolver.resolve(uri)

        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should throw exception for JWK public key`() {
        
        val uri = ("https://mock-server.com/jwk")
        val mockResponse = mapOf(
            PUBLIC_KEY_JWK to "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"...\",\"y\":\"...\"}",
            KEY_TYPE to "EC"
        )
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns mockResponse

        val publicKeyNotFoundException =
            org.junit.jupiter.api.assertThrows<PublicKeyNotFoundException> { resolver.resolve(uri) }

        assertEquals("Public key string not found", publicKeyNotFoundException.message)
    }

    @Test
    fun `should throw exception for HEX public key`() {
        
        val uri = ("https://mock-server.com/hex")
        val mockResponse = mapOf(
            PUBLIC_KEY_HEX to "abcdef123456",
            KEY_TYPE to "EC"
        )
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns mockResponse

        val publicKeyNotFoundException =
            org.junit.jupiter.api.assertThrows<PublicKeyNotFoundException> { resolver.resolve(uri) }

        assertEquals("Public key string not found", publicKeyNotFoundException.message)
    }

    @Test
    fun `should throw exception for Multibase public key`() {
        
        val uri = ("https://mock-server.com/multibase")
        val mockResponse = mapOf(
            PUBLIC_KEY_MULTIBASE to "z6Mki...",
            KEY_TYPE to "EC"
        )
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns mockResponse

        val publicKeyNotFoundException =
            org.junit.jupiter.api.assertThrows<PublicKeyNotFoundException> { resolver.resolve(uri) }

        assertEquals("Public key string not found", publicKeyNotFoundException.message)
    }

    @Test
    fun `should throw PublicKeyTypeNotSupportedException for unknown key type`() {
        
        val uri = ("https://mock-server.com/unknown")
        val mockResponse = mapOf(
            "unknown_key" to "value"
        )
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns mockResponse

        val publicKeyNotFoundException =
            assertThrows(PublicKeyNotFoundException::class.java) { resolver.resolve(uri) }

        assertEquals("Public key string not found", publicKeyNotFoundException.message)
    }

    @Test
    fun `should throw PublicKeyNotFoundException when response is null`() {
        
        val uri = ("https://mock-server.com/empty")
        every { NetworkManagerClient.sendHTTPRequest(uri, any()) } returns null

        assertThrows(PublicKeyNotFoundException::class.java) { resolver.resolve(uri) }
    }
}