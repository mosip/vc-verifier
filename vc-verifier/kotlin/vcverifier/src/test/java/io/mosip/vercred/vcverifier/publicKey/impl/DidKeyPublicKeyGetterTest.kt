package io.mosip.vercred.vcverifier.publicKey.impl

import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.URI

class DidKeyPublicKeyGetterTest {

    private lateinit var didKeyPublicKeyGetter: DidKeyPublicKeyGetter

    @BeforeEach
    fun setUp() {
        didKeyPublicKeyGetter = DidKeyPublicKeyGetter()
    }

    @Test
    fun `should return PublicKey for valid Ed25519 did-key`() {
        val didKeyUri = URI.create("did:key:z6MkpiJgQdNWUzyojaFuCzQ1MWvSSaxUfL1tvbcRfqWFoJRK")

        val publicKey = didKeyPublicKeyGetter.get(didKeyUri)

        assertNotNull(publicKey)
        assertEquals("Ed25519", publicKey.algorithm)
    }

    @Test
    fun `should throw SignatureNotSupportedException for did-key with incorrect decoded byte length`() {
        val didKeyUriTooShort =
            URI.create("did:key:z6MkTestShortTooShortKey")
        val didKeyUriTooLong =
            URI.create("did:key:z6MkTestLongTooLongKeyTooLongKeyTooLongKeyTooLongKey")

        assertThrows<SignatureNotSupportedException> {
            didKeyPublicKeyGetter.get(didKeyUriTooShort)
        }

        assertThrows<SignatureNotSupportedException> {
            didKeyPublicKeyGetter.get(didKeyUriTooLong)
        }
    }
}
