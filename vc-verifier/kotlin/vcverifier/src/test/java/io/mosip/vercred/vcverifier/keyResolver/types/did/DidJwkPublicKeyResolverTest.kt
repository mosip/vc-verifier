package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.mockk.clearAllMocks
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.Test
import java.security.PublicKey
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.testHelpers.validDidJwk
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows
import java.security.spec.InvalidKeySpecException
import java.util.Base64

class DidJwkPublicKeyResolverTest {
    @AfterEach
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }

    @Test
    fun `should resolve JWK successfully for OKP`() {
        val resolver = DidJwkPublicKeyResolver()

        val publicKey: PublicKey = resolver.extractPublicKey(
            createParsedDid(validDidJwk)
        )

        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should resolve JWK successfully for EC`() {
        val jwk = """
        {
            "kty":"EC",
            "alg":"ES256",
            "crv":"P-256",
            "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use":"enc",
            "kid":"1"
        }
    """.trimIndent()

        val did = "did:jwk:${encodeBase64Url(jwk)}"
        val resolver = DidJwkPublicKeyResolver()

        val publicKey = resolver.extractPublicKey(createParsedDid(did))

        assertNotNull(publicKey)
        assertEquals("EC", publicKey.algorithm)
        assertEquals("X.509", publicKey.format)
    }


    @Test
    fun `test invalid base64url`() {
        val invalidDid = "did:jwk:not@valid%base64"
        val resolver = DidJwkPublicKeyResolver()
        val exception = assertThrows<PublicKeyResolutionFailedException> {
            resolver.extractPublicKey(
                createParsedDid(invalidDid)
            )
        }

        assertEquals("Invalid base64url encoding for public key data", exception.message)
    }

    @Test
    fun `test invalid JSON in JWK`() {
        val invalidJsonDid = "did:jwk:${encodeBase64Url("not valid json")}"
        val resolver = DidJwkPublicKeyResolver()
        val exception = assertThrows<UnknownException> {
            resolver.extractPublicKey(
                createParsedDid(invalidJsonDid)
            )
        }

        assertEquals("Error while getting public key object", exception.message)
    }

    @Test
    fun `test unsupported curve`() {
        val jwk = """
            {
                "kty": "OKP",
                "crv": "P-256",
                "alg": "ES256",
                "use":"sig",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            }
        """.trimIndent()
        val unsupportedCurveDid = "did:jwk:${encodeBase64Url(jwk)}"
        val resolver = DidJwkPublicKeyResolver()
        val exception = assertThrows<UnknownException> {
            resolver.extractPublicKey(
                createParsedDid(unsupportedCurveDid)
            )
        }

        assertEquals("Error while getting public key object", exception.message)
    }

    @Test
    fun `test unsupported key type`() {
        val jwk = """
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "sXch9z_AqKXohRAAE2Aw53zrk9B3QHkMbhZNEQURnPvDPjGvqX2m-d0emw7np2ROmMUT_k0rAj6kgaHQnxKm3w",
            "e": "AQAB"
        }
    """.trimIndent()
        val unsupportedKeyTypeDid = "did:jwk:${encodeBase64Url(jwk)}"
        val resolver = DidJwkPublicKeyResolver()

        val exception = assertThrows<PublicKeyTypeNotSupportedException> {
            resolver.extractPublicKey(
                createParsedDid(unsupportedKeyTypeDid)
            )
        }
        assertEquals("KeyType - RSA is not supported. Supported: OKP, EC", exception.message)
    }

    @Test
    fun `test missing x coordinate`() {
        val jwk = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA"
            }
        """.trimIndent()
        val missingXDid = "did:jwk:${encodeBase64Url(jwk)}"
        val resolver = DidJwkPublicKeyResolver()

        val exception = assertThrows<UnknownException> {
            resolver.extractPublicKey(
                createParsedDid(missingXDid)
            )
        }
        assertEquals("Error while getting public key object", exception.message)
    }

    @Test
    fun `test invalid x coordinate base64`() {
        val jwk = """
            {
                "kty": "OKP",
                "use": "sig",
                "crv": "Ed25519",
                "x": "invalid@base64",
                "alg": "EdDSA"
            }
        """.trimIndent()
        val invalidXBase64Did = "did:jwk:${encodeBase64Url(jwk)}"
        val resolver = DidJwkPublicKeyResolver()

        val exception = assertThrows<PublicKeyResolutionFailedException> {
            resolver.extractPublicKey(
                createParsedDid(invalidXBase64Did)
            )
        }
        assertEquals("Invalid base64url encoding for public key data", exception.message)
    }

    @Test
    fun `test invalid public key data`() {
        val jwk = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "aW52YWxpZCBrZXkgZGF0YQ==",
                "alg": "EdDSA",
                "use": "sig"
            }
        """.trimIndent()
        val invalidKeyDataDid = "did:jwk:${encodeBase64Url(jwk)}"
        val resolver = DidJwkPublicKeyResolver()

        val exception = assertThrows<InvalidKeySpecException> {
            resolver.extractPublicKey(
                createParsedDid(invalidKeyDataDid)
            )
        }
        assertEquals("raw key data not recognised", exception.message)
    }

    private fun createParsedDid(didJwk: String) = ParsedDID(
        didJwk,
        DidMethod.JWK,
        didJwk.split("did:jwk:")[1],
        didJwk,
    )


    private fun encodeBase64Url(input: String): String =
        Base64.getUrlEncoder().withoutPadding()
            .encodeToString(input.toByteArray(Charsets.UTF_8))
}