package io.mosip.vercred.vcverifier.publicKey.impl

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import io.mosip.vercred.vcverifier.exception.UnknownException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.security.spec.InvalidKeySpecException
import java.util.Base64

class DidJwkPublicKeyGetterTest {

    private lateinit var didJwkPublicKeyGetter: DidJwkPublicKeyGetter

    @BeforeEach
    fun setUp() {

        didJwkPublicKeyGetter = DidJwkPublicKeyGetter()
    }

    @Test
    fun `should return PublicKey for valid did-jwk Ed25519`() {
        val verificationMethodUri = URI.create("did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImtldWxwNGVVU0d1eEVLSDlzQ0JkaTN1ek1sQmQ4cE1wMVdlamhTUFZybUEiLCJhbGciOiJFZDI1NTE5In0#0")
        val publicKey = didJwkPublicKeyGetter.get(verificationMethodUri)

        assertNotNull(publicKey)
        assertEquals("Ed25519", publicKey.algorithm)
    }

    @Test
    fun `should throw UnknownException for JWK with missing x component`() {
        val jwkWithoutX = """{"kty":"OKP","crv":"Ed25519"}"""
        val encodedJwk =
            Base64.getUrlEncoder().encodeToString(jwkWithoutX.toByteArray())
        val didJwk = "did:jwk:$encodedJwk#key1"
        val verificationMethodUri = URI.create(didJwk)

        assertThrows<UnknownException> {
            didJwkPublicKeyGetter.get(verificationMethodUri)
        }
    }

    @Test
    fun `should throw IllegalArgumentException for JWK with unsupported curve`() {
        val publicKeyX =
            "z6_4V5N3N3c2N3g2N3i2N3j2N3k2N3l2N3m2N3n2N3o2N3p2N3q2N3r2N3s2N3t2N3u2N3v2N3w2N3x"
        val jwkUnsupportedCurve =
            OctetKeyPair.Builder(Curve.X25519, Base64URL.from(String(Base64.getUrlDecoder().decode(publicKeyX))))
                .build()
        val encodedJwk =
            Base64.getUrlEncoder().encodeToString(jwkUnsupportedCurve.toJSONString().toByteArray())
        val didJwk = "did:jwk:$encodedJwk#key1"
        val verificationMethodUri = URI.create(didJwk)

        assertThrows<IllegalArgumentException> {
            didJwkPublicKeyGetter.get(verificationMethodUri)
        }
    }


    @Test
    fun `should throw InvalidKeySpecException for invalid public key bytes format`() {

        val didJwk = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImFHVnNiR3h2YnciLCJhbGciOiJFZDI1NTE5In0#key1"
        val verificationMethodUri = URI.create(didJwk)

        assertThrows<InvalidKeySpecException> {
            didJwkPublicKeyGetter.get(verificationMethodUri)
        }
    }
}