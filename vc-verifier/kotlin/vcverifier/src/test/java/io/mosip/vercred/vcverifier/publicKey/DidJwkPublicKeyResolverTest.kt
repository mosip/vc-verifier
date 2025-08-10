package io.mosip.vercred.vcverifier.publicKey

import io.mosip.vercred.vcverifier.publicKey.impl.DidJwkPublicKeyResolver
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.Test
import java.net.URI
import java.security.PublicKey
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.UnknownException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows
import java.security.spec.InvalidKeySpecException

class DidJwkPublicKeyResolverTest {
    private val didJwk =
        URI("did:jwk:eyJrdHkiOiAiT0tQIiwgImNydiI6ICJFZDI1NTE5IiwgIngiOiAiOGc5ZF9NQjBpVTJubWdiXzlQNERmMFRSUW01UkpUbWFpRWsySGtaeTVwRSIsICJhbGciOiAiRWREU0EiLCAia2V5X29wcyI6IFsidmVyaWZ5Il0sICJ1c2UiOiAic2lnIn0")

    @Test
    fun `should resolve JWK successfully`() {
        val resolver = DidJwkPublicKeyResolver()

        val publicKey: PublicKey = resolver.resolve(didJwk)

        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }


    private fun encodeBase64Url(input: String): String =
        java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(input.toByteArray(Charsets.UTF_8))

    @Test
    fun `test invalid base64url`() {
        val invalidDid = "did:jwk:not@valid%base64"
        val resolver = DidJwkPublicKeyResolver()
        val exception = assertThrows<PublicKeyResolutionFailedException> {
            resolver.resolve(URI(invalidDid))
        }

        assertEquals("Invalid base64url encoding for public key data", exception.message)
    }

    @Test
    fun `test invalid JSON in JWK`() {
        val invalidJsonDid = "did:jwk:${encodeBase64Url("not valid json")}"
        val resolver = DidJwkPublicKeyResolver()
        val exception = assertThrows<UnknownException> {
            resolver.resolve(URI(invalidJsonDid))
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
            resolver.resolve(URI(unsupportedCurveDid))
        }

        assertEquals("Error while getting public key object", exception.message)
    }

    @Test
    fun `test unsupported key type`() {
        val jwk = """
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use":"sig",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            }
        """.trimIndent()
        val unsupportedKeyTypeDid = "did:jwk:${encodeBase64Url(jwk)}"
        val resolver = DidJwkPublicKeyResolver()

        val exception = assertThrows<PublicKeyTypeNotSupportedException> {
            resolver.resolve(URI(unsupportedKeyTypeDid))
        }
        assertEquals("KeyType - EC is not supported. Supported: OKP", exception.message)
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
            resolver.resolve(URI(missingXDid))
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
            resolver.resolve(URI(invalidXBase64Did))
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
            resolver.resolve(URI(invalidKeyDataDid))
        }
        assertEquals("raw key data not recognised", exception.message)
    }
}