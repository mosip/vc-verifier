package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyFromHex
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyFromJWK
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

class PublicKeyUtilsTest{
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
        val publicKey: PublicKey = getPublicKeyFromJWK(jwkString,ES256K_KEY_TYPE_2019)

        assertNotNull(publicKey)
        assertTrue(publicKey is ECPublicKey)
        assertEquals("EC", publicKey.algorithm)
    }

    @Test
    fun `should correctly generate PublicKey from valid compressed secp256k1 hex`() {
        // Valid compressed secp256k1 public key (33 bytes)
        val compressedHexKey = "034ee0f670fc96bb75e8b89c068a1665007a41c98513d6a911b6137e2d16f1d300"

        val publicKey = getPublicKeyFromHex(compressedHexKey,ES256K_KEY_TYPE_2019)

        assertNotNull(publicKey, "Public key should not be null")
        assertTrue(publicKey is ECPublicKey, "Returned key should be an instance of ECPublicKey")
        assertEquals("EC", publicKey.algorithm)
    }
}