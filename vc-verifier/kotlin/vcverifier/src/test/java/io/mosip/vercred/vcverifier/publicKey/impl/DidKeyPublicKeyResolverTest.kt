package io.mosip.vercred.vcverifier.publicKey.impl

import io.ipfs.multibase.Base58
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.testHelpers.assertPublicKey
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.URI
import java.security.PublicKey

class DidKeyPublicKeyResolverTest {

    private val resolver = DidKeyPublicKeyResolver()

    @Test
    fun `should resolve valid Ed25519 did key`() {
        val validDidKey = URI("did:key:z6MkpiJgQdNWUzyojaFuCzQ1MWvSSaxUfL1tvbcRfqWFoJRK")
        val publicKey: PublicKey = resolver.resolve(validDidKey)

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
        val unsupportedKeyTypeDidKey = URI("did:key:$multibase")

        val keyTypeNotSupportedException = assertThrows(PublicKeyTypeNotSupportedException::class.java) {
            resolver.resolve(unsupportedKeyTypeDidKey)
        }
        assertEquals("KeyType - 18 is not supported. Supported: ed25519", keyTypeNotSupportedException.message)
    }

    @Test
    fun `should throw UnknownException for invalid multibase encoding`() {
        val invaliBas58DidKey = URI("did:key:zINVALIDBASE58")

        val invalidBase58Exception = assertThrows(IllegalStateException::class.java) {
            resolver.resolve(invaliBas58DidKey)
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
        val invalidKeySizeDidKey = URI("did:key:$multibase")

        val exception = assertThrows(PublicKeyTypeNotSupportedException::class.java) {
            resolver.resolve(invalidKeySizeDidKey)
        }
        assertTrue(exception.message!!.contains("KeyType -"))
    }
}