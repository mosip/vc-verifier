package io.mosip.vercred.vcverifier.publicKey.types.did

import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.verify
import io.mosip.vercred.vcverifier.constants.DidMethod
import io.mosip.vercred.vcverifier.publicKey.ParsedDID
import io.mosip.vercred.vcverifier.publicKey.impl.DidKeyPublicKeyResolver
import io.mosip.vercred.vcverifier.publicKey.impl.DidWebPublicKeyResolver
import io.mosip.vercred.vcverifier.publicKey.types.did.types.DidJwkPublicKeyResolver
import io.mosip.vercred.vcverifier.testHelpers.validDidJwk
import io.mosip.vercred.vcverifier.testHelpers.validDidKey
import io.mosip.vercred.vcverifier.testHelpers.validDidWeb
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI

class DidPublicKeyResolverTest {
    @BeforeEach
    fun setUp() {
        mockkConstructor(DidJwkPublicKeyResolver::class)
        mockkConstructor(DidKeyPublicKeyResolver::class)
        mockkConstructor(DidWebPublicKeyResolver::class)
    }

    @Test
    fun `should call Did Jwk resolver when the input did is of method type jwk`() {
        val didPublicKeyResolver = DidPublicKeyResolver()
        every {
            anyConstructed<DidJwkPublicKeyResolver>().extractPublicKey(
                any(),
                any()
            )
        } returns mockk()


        didPublicKeyResolver.resolve(validDidJwk)

        verify(exactly = 1) {
            anyConstructed<DidJwkPublicKeyResolver>().extractPublicKey(any(), any())
        }
    }

    @Test
    fun `should call Did Key resolver when the input did is of method type key`() {
        val didPublicKeyResolver = DidPublicKeyResolver()
        every {
            anyConstructed<DidKeyPublicKeyResolver>().extractPublicKey(
                any(),
                any()
            )
        } returns mockk()


        didPublicKeyResolver.resolve(validDidKey)

        verify(exactly = 1) {
            anyConstructed<DidKeyPublicKeyResolver>().extractPublicKey(
                ParsedDID(
                    did = validDidKey,
                    method = DidMethod.KEY,
                    id = validDidKey.split("did:key:")[1],
                    didUrl = validDidKey
                ), null
            )
        }
    }

    @Test
    fun `should call Did web resolver when the input did is of method type web`() {
         val validDid = "$validDidWeb#key-1"
        val didPublicKeyResolver = DidPublicKeyResolver()
        every {
            anyConstructed<DidWebPublicKeyResolver>().extractPublicKey(
                any(),
                any()
            )
        } returns mockk()

        didPublicKeyResolver.resolve(validDid)

        verify(exactly = 1) {
            anyConstructed<DidWebPublicKeyResolver>().extractPublicKey(
                ParsedDID(
                    did = validDidWeb,
                    method = DidMethod.WEB,
                    id = "example.com",
                    didUrl = validDid,
                    fragment = "key-1"
                ), null
            )
        }
    }
}