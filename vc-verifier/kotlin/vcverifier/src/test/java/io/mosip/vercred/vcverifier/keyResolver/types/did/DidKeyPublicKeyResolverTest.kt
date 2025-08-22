package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.ipfs.multibase.Base58
import io.mockk.clearAllMocks
import io.mockk.unmockkAll
import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import io.mosip.vercred.vcverifier.testHelpers.validDidKey
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.PublicKey

class DidKeyPublicKeyResolverTest {
    @AfterEach
    fun tearDown() {
        clearAllMocks()
        unmockkAll()
    }

    private val resolver = DidKeyPublicKeyResolver()

    @Test
    fun `should resolve valid Ed25519 did key`() {
        val publicKey: PublicKey = resolver.extractPublicKey(createParsedDid(validDidKey))

        val expectedEncodedPublicKey =
            "[48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, -104, 111, -113, -128, 30, 39, -124, -13, 109, 42, -42, -40, -42, 108, 43, 71, -113, 52, 13, 48, -52, 87, 69, -103, 118, 53, 52, 53, 86, 66, -93, 22]"
        assertPublicKey(publicKey, expectedEncodedPublicKey)
    }

    @Test
    fun `should throw PublicKeyTypeNotSupportedException for unsupported key type`() {
        val prefix = byteArrayOf(0x12, 0x34)
        val pubKey = ByteArray(32) { 0x01 }
        val multicodec = prefix + pubKey
        val multibase = "z" + Base58.encode(multicodec).toString()
        val unsupportedKeyTypeDidKey = ("did:key:$multibase")

        val keyTypeNotSupportedException =
            assertThrows(PublicKeyTypeNotSupportedException::class.java) {
                resolver.extractPublicKey(createParsedDid(unsupportedKeyTypeDidKey))
            }
        assertEquals(
            "KeyType - 18 is not supported. Supported: ed25519",
            keyTypeNotSupportedException.message
        )
    }

    @Test
    fun `should throw UnknownException for invalid multibase encoding`() {
        val invalidBas58DidKey = "did:key:zINVALIDBASE58"

        val invalidBase58Exception = assertThrows(IllegalStateException::class.java) {
            resolver.extractPublicKey(createParsedDid(invalidBas58DidKey))
        }
        assertEquals("InvalidCharacter in base 58", invalidBase58Exception.message)
    }

    @Test
    fun `should throw exception for valid prefix but invalid key size`() {
        // Ed25519 prefix but only 10 bytes instead of 32
        val prefix = byteArrayOf(0xed.toByte(), 0x01.toByte())
        val pubKey = ByteArray(10) { 0x01 }
        val multicodec = prefix + pubKey
        val multibase = "z" + Base58.encode(multicodec).toString()
        val invalidKeySizeDidKey = "did:key:$multibase"

        val exception = assertThrows(PublicKeyTypeNotSupportedException::class.java) {
            resolver.extractPublicKey(createParsedDid(invalidKeySizeDidKey))
        }
        assertTrue(exception.message!!.contains("KeyType -"))
    }

    private fun createParsedDid(didKey: String) = ParsedDID(
        didKey,
        DidMethod.KEY,
        didKey.split("did:key:")[1],
        didKey,
    )
}