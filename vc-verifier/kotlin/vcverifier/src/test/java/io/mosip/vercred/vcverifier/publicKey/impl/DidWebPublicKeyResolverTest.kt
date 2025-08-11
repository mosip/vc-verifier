package io.mosip.vercred.vcverifier.publicKey.impl

import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.networkManager.HTTP_METHOD
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import org.junit.Ignore
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI
import java.security.PublicKey

class DidWebPublicKeyResolverTest {

    private val resolver = DidWebPublicKeyResolver()

    private fun didUrl(keyId: String = "key-1") = "did:web:example.com#$keyId"
    private fun didDocWithMethod(method: Map<String, Any>) = mapOf("verificationMethod" to listOf(method))

    @BeforeEach
    fun setUp() {
        mockkObject(NetworkManagerClient.Companion)
    }

    @Test
    fun `should resolve public key from PEM`() {
        val pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=\n-----END PUBLIC KEY-----"
        val method = mapOf("id" to didUrl(), "publicKeyPem" to pem, "type" to "Ed25519VerificationKey2020")
        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } returns didDocWithMethod(method)

        val result = resolver.resolve(URI(didUrl()))
        assertNotNull(result)
    }

    @Test
    fun `should resolve public key from multibase`() {
        val method = mapOf("id" to didUrl("key-2"), "publicKeyMultibase" to "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", "type" to "Ed25519VerificationKey2020")
        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } returns didDocWithMethod(method)

        val result = resolver.resolve(URI(didUrl("key-2")))
        assertNotNull(result)
    }

//    @Test
//    @Ignore("Skipping EC publicKeyJwk support test for now")
//    fun `should resolve public key from JWK`() {
//        val method = mapOf("id" to didUrl("key-3"), "publicKeyJwk" to """
//            {
//              "kty": "EC",
//              "use": "sig",
//              "key_ops": [
//                "sign"
//              ],
//              "alg": "ES256",
//              "kid": "0651615e-2635-4208-bca6-50da06e92325",
//              "crv": "secp256k1",
//              "x": "bCury1lZwj-VCpqjO3SwxiMCcreBXsFK0eGngDp35gU",
//              "y": "qqrQJ87YE5Z6SHjWQz_BAzoutx0xmj_uvAdsXVQj0-I",
//              "d": "UrbIp0R6ECL-LqzKw0-ITYaKgnNuvs5znqLHQDmTats"
//            }
//        """.trimIndent(), "type" to "EcdsaSecp256k1VerificationKey2019")
//        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } returns didDocWithMethod(method)
//
//        val result = resolver.resolve(URI(didUrl("key-3")))
//        assertNotNull(result)
//    }

//    @Test
////    "Skipping EC publicKeyHex support test for now"
//    fun `should resolve public key from HEX`() {
//        val method = mapOf("id" to didUrl("key-4"), "publicKeyHex" to "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691", "type" to ES256K_KEY_TYPE_2019)
//        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } returns didDocWithMethod(method)
//        val result = resolver.resolve(URI(didUrl("key-4")))
//
//        assertNotNull(result)
//    }

    @Test
    fun `should throw when verification method not found`() {
        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } returns emptyMap()

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-5")))
        }
        assertTrue(ex.message!!.contains("Verification method not found"))
    }

    @Test
    fun `should throw when no matching verification method`() {
        val method = mapOf("id" to "did:web:example.com#other-key")
        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } returns didDocWithMethod(method)

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-6")))
        }
        assertTrue(ex.message!!.contains("No verification methods available"))
    }

    @Test
    fun `should throw when none of the provided keys found`() {
        val method = mapOf("id" to didUrl("key-7"))
        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } returns didDocWithMethod(method)

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-7")))
        }
        assertTrue(ex.message!!.contains("None of the provided keys"))
    }

    @Test
    fun `should throw when public key type is not supported`() {
        val method = mapOf("id" to didUrl("key-8"), "unsupportedKey" to "value")
        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } returns didDocWithMethod(method)

        val exception = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-8")))
        }
        assertEquals("None of the provided keys were found in verification method",exception.message)
    }

    @Test
    fun `should throw PublicKeyNotFoundException on network call to resolve did document fails`() {
        every { sendHTTPRequest("https://example.com/.well-known/did.json", HTTP_METHOD.GET) } throws RuntimeException("network error")

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-9")))
        }
        assertTrue(ex.message!!.contains("network error"))
    }
}