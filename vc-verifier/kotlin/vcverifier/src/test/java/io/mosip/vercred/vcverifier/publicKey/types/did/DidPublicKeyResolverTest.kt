package io.mosip.vercred.vcverifier.publicKey.types.did

import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.verify
import io.mosip.vercred.vcverifier.publicKey.types.did.types.DidJwkPublicKeyResolver
import io.mosip.vercred.vcverifier.testHelpers.validDidJwk
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI

class DidPublicKeyResolverTest {
    @BeforeEach
    fun setUp() {
        mockkConstructor(DidJwkPublicKeyResolver::class)
    }

    @Test
    fun `should call Did Jwk resolver when the input did is of method type jwk`() {
        val didPublicKeyResolver = DidPublicKeyResolver()
        every { anyConstructed<DidJwkPublicKeyResolver>().extractPublicKey(any(), any()) } returns mockk()


        didPublicKeyResolver.resolve(URI(validDidJwk))

        verify(exactly = 1) {
            anyConstructed<DidJwkPublicKeyResolver>().extractPublicKey(any(), any())
        }
    }
}