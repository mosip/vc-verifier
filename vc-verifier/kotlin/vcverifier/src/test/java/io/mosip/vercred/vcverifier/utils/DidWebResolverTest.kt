import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.DidWebResolver
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidDocumentNotFound
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidResolutionFailed
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.networkManager.HTTP_METHOD
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class DidWebResolverTest {

    @Test
    fun `parse invalid did url should throw UnsupportedDidUrl`() {
        val invalidDidUrl = "invalidDid:web:example.com"
        assertThrows <UnsupportedDidUrl> { DidWebResolver(invalidDidUrl).resolve() }
    }

    @Test
    fun `resolve should return document when valid`() {
        val didUrl = "did:web:example.com:user"
        val mockResponse = mapOf("id" to didUrl)

        mockkObject(NetworkManagerClient.Companion)
        every { sendHTTPRequest("https://example.com/user/did.json", HTTP_METHOD.GET) } returns mockResponse

        val resolvedDoc = DidWebResolver(didUrl).resolve()
        assertEquals( resolvedDoc, mapOf("id" to didUrl))
    }

    @Test
    fun `should throw DidDocumentNotFound when document is missing`() {
        val didUrl = "did:web:nonexistent.com:user"

        mockkObject(NetworkManagerClient.Companion)
        every { sendHTTPRequest("https://nonexistent.com/user/did.json", HTTP_METHOD.GET) } returns null

        val exception = assertThrows<DidResolutionFailed> { DidWebResolver(didUrl).resolve() }
        assertEquals("Did document could not be fetched", exception.message)

    }

    @Test
    fun `resolve  throw UnsupportedDidUrl when did web url is not given`() {
        val didUrl = "did:key:nonexistent.com:user"

        val exception = assertThrows<UnsupportedDidUrl> { DidWebResolver(didUrl).resolve() }
        assertEquals("Given did url is not supported", exception.message)
    }

    // New tests for URL resolution


    @Test
    fun `should resolve DID with only domain to well-known path`() {
        fun `resolve should return document when valid without path components`() {
            val didUrl = "did:web:example.com"
            val mockResponse = mapOf("id" to didUrl)

            mockkObject(NetworkManagerClient.Companion)
            every {
                sendHTTPRequest(
                    "https://example.com/.well-known/did.json",
                    HTTP_METHOD.GET
                )
            } returns mockResponse

            val resolvedDoc = DidWebResolver(didUrl).resolve()
            assertEquals(resolvedDoc, mapOf("id" to didUrl))
        }

    }

        @Test
    fun `should resolve DID with multiple path components to correct URL`() {
        val didUrl = "did:web:example.com:user:alice"
        val mockResponse = mapOf("id" to didUrl)

        mockkObject(NetworkManagerClient.Companion)
        every { sendHTTPRequest("https://example.com/user/alice/did.json", HTTP_METHOD.GET) } returns mockResponse

        val resolvedDoc = DidWebResolver(didUrl).resolve()
        assertEquals(resolvedDoc, mapOf("id" to didUrl))
    }

    @Test
    fun `should resolve DID with single path component to correct URL`() {
        val didUrl = "did:web:example.com:path1"
        val mockResponse = mapOf("id" to didUrl)

        mockkObject(NetworkManagerClient.Companion)
        every { sendHTTPRequest("https://example.com/path1/did.json", HTTP_METHOD.GET) } returns mockResponse

        val resolvedDoc = DidWebResolver(didUrl).resolve()
        assertEquals(resolvedDoc, mapOf("id" to didUrl))
    }
}