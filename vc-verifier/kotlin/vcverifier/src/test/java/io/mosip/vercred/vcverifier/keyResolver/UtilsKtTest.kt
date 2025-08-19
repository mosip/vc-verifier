package io.mosip.vercred.vcverifier.keyResolver

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

class UtilsKtTest {
    @Test
    fun `test EC secp256k1 public key extraction`() {
        val jwkString = """
    {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "STRMr8BN3ToqGYWQExEm5-mjyiSqq9iGs600-4UMiZY",
        "y": "wMC2jyYYA1UPz5TjeHRkSAZV6y6_C5oyCPsudWtFQPM"
    }
    """.trimIndent()
        val publicKey: PublicKey = getPublicKeyFromJWK(jwkString, ES256K_KEY_TYPE_2019)

        assertNotNull(publicKey)
        assertTrue(publicKey is ECPublicKey)
        assertEquals("EC", publicKey.algorithm)
    }

    @Test
    fun `should correctly generate PublicKey from valid compressed secp256k1 hex`() {
        // Valid compressed secp256k1 public key (33 bytes)
        val compressedHexKey = "034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300"

        val publicKey = getPublicKeyFromHex(compressedHexKey, ES256K_KEY_TYPE_2019)

        assertNotNull(publicKey, "Public key should not be null")
        assertTrue(publicKey is ECPublicKey, "Returned key should be an instance of ECPublicKey")
        assertEquals("EC", publicKey.algorithm)
    }

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

        assertEquals(
            "Missing the public key data in JWK",
            publicKeyResolutionFailedException.message
        )
    }

    @Test
    fun `should throw error when curve is not supported`() {
        val edPublicKey = mapOf(
            "kty" to "OKP",
            "crv" to "P-256",
            "x" to "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        )
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
        val edPublicKey = mapOf(
            "kty" to "EC",
            "crv" to "Ed25519",
            "x" to "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
        )
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

        assertPublicKey(
            publicKey,
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -14, 15, 93, -4, -64, 116, -119, 77, -89, -102, 6, -1, -12, -2, 3, 127, 68, -47, 66, 110, 81, 37, 57, -102, -120, 73, 54, 30, 70, 114, -26, -111]"
        )
    }

    @Test
    fun `should throw error when public key hex of the Ed key is not 32 bytes`() {
        val invalidEdPublicKeyHex = "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4"

        val exception =
            assertThrows<IllegalArgumentException> { getEdPublicKeyFromHex(invalidEdPublicKeyHex) }

        assertEquals("Ed25519 public key must be 32 bytes", exception.message)
    }
}