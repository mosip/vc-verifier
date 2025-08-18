package io.mosip.vercred.vcverifier.publicKey.impl

import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.networkManager.HTTP_METHOD
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI

class DidWebPublicKeyResolverTest {

    private val resolver = DidWebPublicKeyResolver()

    private fun didUrl(keyId: String = "key-1") = "did:web:example.com#$keyId"
    private fun didDocWithMethod(method: Map<String, Any>) =
        mapOf("verificationMethod" to listOf(method))

    @BeforeEach
    fun setUp() {
        mockkObject(NetworkManagerClient.Companion)
    }

    // Key type - Ed25519VerificationKey2020

    @Test
    fun `should resolve public key from PEM of Ed25519 key type`() {
        val pem =
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=\n-----END PUBLIC KEY-----"
        val method =
            mapOf("id" to didUrl(), "publicKeyPem" to pem, "type" to "Ed25519VerificationKey2020")
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(method)

        val result = resolver.resolve(URI(didUrl()))
        assertNotNull(result)
    }

    @Test
    fun `should resolve public key from multibase of Ed25519 key type`() {
        val method = mapOf(
            "id" to didUrl("key-2"),
            "publicKeyMultibase" to "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "type" to "Ed25519VerificationKey2020"
        )
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(method)

        val result = resolver.resolve(URI(didUrl("key-2")))
        assertNotNull(result)
    }

    @Test
    fun `should resolve publicKeyJwk of Ed25519 key type`() {
        val method = mapOf(
            "id" to didUrl("key-2"), "publicKeyJwk" to """
            {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "8g9d_MB0iU2nmgb_9P4Df0TRQm5RJTmaiEk2HkZy5pE",
                    "alg": "EdDSA",
                    "use": "sig"
                }
        """.trimIndent(), "type" to "Ed25519VerificationKey2020"
        )
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(method)

        val result = resolver.resolve(URI(didUrl("key-2")))

        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        assertPublicKey(result, expectedEncodedPublicKey)
    }

    @Test
    fun `should resolve publicKeyHex of Ed25519 key type`() {
        val method = mapOf(
            "id" to didUrl("key-2"),
            "publicKeyHex" to "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691",
            "type" to "Ed25519VerificationKey2020"
        )
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(method)

        val resolvedPublicKey = resolver.resolve(URI(didUrl("key-2")))

        assertPublicKey(
            resolvedPublicKey,
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        )
    }

    // Key type - EcdsaSecp256k1VerificationKey2019

    @Test
    fun `should resolve public key from JWK of ES256K key type`() {
        val keyId = didUrl("key-3")
        val method = mapOf(
            "id" to keyId, "publicKeyJwk" to """
            {
                "kty": "EC",
                "use": "sig",
                "crv": "secp256k1",
                "kid": "sig-1755418456",
                "x": "2-LgLeBUdAXGKuhGRuXL2OmoOLOOA6gD9TcX0zLwOjY",
                "y": "ZDtDKZNZQxtTo628V5nlaKDG2QiURVPje22p6CmNjdo",
                "alg": "ES256K"
            }
        """.trimIndent(), "type" to "EcdsaSecp256k1VerificationKey2019"
        )
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(method)

        val result = resolver.resolve(URI(didUrl("key-3")))
        assertNotNull(result)
    }

//    @Test
//    fun `should resolve public key from PEM of ES256K key type`() {
//        val jwkJson = """
//{
//  "kty": "EC",
//  "crv": "secp256k1",
//  "x": "2-LgLeBUdAXGKuhGRuXL2OmoOLOOA6gD9TcX0zLwOjY",
//  "y": "ZDtDKZNZQxtTo628V5nlaKDG2QiURVPje22p6CmNjdo"
//}
//"""
//
//
//        val publicKeyPem =
//            """
//
//            """.trimIndent()
//
//        val keyId = didUrl("key-3")
//        val method = mapOf(
//            "id" to keyId,
//            "publicKeyPem" to publicKeyPem,
//            "type" to "EcdsaSecp256k1VerificationKey2019"
//        )
//        every {
//            sendHTTPRequest(
//                "https://example.com/.well-known/did.json",
//                HTTP_METHOD.GET
//            )
//        } returns didDocWithMethod(method)
//
//        val result = resolver.resolve(URI(didUrl("key-3")))
//        assertNotNull(result)
//    }
//
//    @Test
//    fun `should resolve public key from multibase of ES256K key type`() {
//        jWKtoMultibase()
//        val keyId = didUrl("key-3")
//        val method = mapOf(
//            "id" to keyId,
//            "publicKeyMultibase" to "z7r8osshHmX3ChCLA2D7Hcr1ubWXZtehU3PMztvyaGmrQRgS5fwm4cn1LgqEDjJpCteNszF6E6gL3VZUecVXyYinEtt5X",
//            "type" to "EcdsaSecp256k1VerificationKey2019"
//        )
//        every {
//            sendHTTPRequest(
//                "https://example.com/.well-known/did.json",
//                HTTP_METHOD.GET
//            )
//        } returns didDocWithMethod(method)
//
//        val result = resolver.resolve(URI(didUrl("key-3")))
//        assertNotNull(result)
//    }

    @Test
    fun `should resolve public key from HEX of ES256K key type`() {
        val didInfo = mapOf(
            "id" to didUrl("key-4"),
            "publicKeyHex" to "02dbe2e02de0547405c62ae84646e5cbd8e9a838b38e03a803f53717d332f03a36",
            "type" to ES256K_KEY_TYPE_2019
        )
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(didInfo)
        val result = resolver.resolve(URI(didUrl("key-4")))

        assertNotNull(result)
    }

    @Test
    fun `should throw when verification method not found`() {
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns emptyMap()

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-5")))
        }
        assertTrue(ex.message!!.contains("Verification method not found"))
    }

    @Test
    fun `should throw when no matching verification method`() {
        val method = mapOf("id" to "did:web:example.com#other-key")
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(method)

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-6")))
        }
        assertTrue(ex.message!!.contains("No verification methods available"))
    }

    @Test
    fun `should throw when none of the provided keys found`() {
        val method = mapOf("id" to didUrl("key-7"))
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(method)

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-7")))
        }
        assertTrue(ex.message!!.contains("None of the provided keys"))
    }

    @Test
    fun `should throw when public key type is not supported`() {
        val method = mapOf("id" to didUrl("key-8"), "unsupportedKey" to "value")
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } returns didDocWithMethod(method)

        val exception = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-8")))
        }
        assertEquals(
            "None of the provided keys were found in verification method",
            exception.message
        )
    }

    @Test
    fun `should throw PublicKeyNotFoundException on network call to resolve did document fails`() {
        every {
            sendHTTPRequest(
                "https://example.com/.well-known/did.json",
                HTTP_METHOD.GET
            )
        } throws RuntimeException("network error")

        val ex = assertThrows(PublicKeyNotFoundException::class.java) {
            resolver.resolve(URI(didUrl("key-9")))
        }
        assertTrue(ex.message!!.contains("network error"))
    }
}