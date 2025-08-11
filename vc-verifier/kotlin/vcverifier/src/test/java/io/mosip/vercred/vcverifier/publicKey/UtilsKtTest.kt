package io.mosip.vercred.vcverifier.publicKey

import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class UtilsKtTest {
    @Test
    fun `should return public key for Ed public key in JWK format`() {
        val edPublicKeyJwk = mapOf(
            "kty" to "OKP",
            "crv" to "Ed25519",
            "x" to "8g9d_MB0iU2nmgb_9P4Df0TRQm5RJTmaiEk2HkZy5pE",
            "alg" to "EdDSA",
            "use" to "sig"
        )
        val edPublicKey = getEdPublicKey(edPublicKeyJwk)

        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        assertPublicKey(edPublicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should throw exception when Ed public key in JWK format does not have x`() {
        val edPublicKeyJwk = mapOf(
            "kty" to "OKP",
            "crv" to "Ed25519",
            "alg" to "EdDSA",
            "use" to "sig"
        )
        val publicKeyResolutionFailedException =
            assertThrows<PublicKeyResolutionFailedException> { getEdPublicKey(edPublicKeyJwk) }

        assertEquals("Missing the public key data in JWK",publicKeyResolutionFailedException.message)
    }

    @Test
    fun `should throw error when curve is not supported`() {
        val edPublicKey = mapOf("kty" to "OKP",
        "crv" to  "P-256",
        "x" to  "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691")
        val exception = assertThrows<PublicKeyResolutionFailedException> {
            getEdPublicKey(edPublicKey)
        }

        assertEquals(
            "Curve - P-256 is not supported. Supported: Ed25519",
            exception.message
        )
    }

    @Test
    fun `should throw error when key type is not supported`() {
        val edPublicKey = mapOf("kty" to  "EC",
        "crv" to  "Ed25519",
        "x" to  "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691")
        val exception = assertThrows<PublicKeyResolutionFailedException> {
            getEdPublicKey(edPublicKey)
        }

        assertEquals(
            "KeyType - EC is not supported. Supported: OKP",
            exception.message
        )
    }

    @Test
    fun `should return Ed public key for hex format input`() {
        val validEdPublicKeyHex = "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"

        val publicKey =
            getEdPublicKeyFromHex(validEdPublicKeyHex)

        assertPublicKey(publicKey, "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]")
    }

    @Test
    fun `should throw error when public key hex of the Ed key is not 32 bytes`() {
        val invalidEdPublicKeyHex = "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4"

        val exception =
            assertThrows<IllegalArgumentException> { getEdPublicKeyFromHex(invalidEdPublicKeyHex) }

        assertEquals("Ed25519 public key must be 32 bytes",exception.message)
    }
}