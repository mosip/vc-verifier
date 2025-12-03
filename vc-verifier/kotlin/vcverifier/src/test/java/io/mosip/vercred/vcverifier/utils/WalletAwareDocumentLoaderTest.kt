package io.mosip.vercred.vcverifier.utils

import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.loader.DocumentLoader
import com.apicatalog.jsonld.loader.DocumentLoaderOptions
import io.mosip.vercred.vcverifier.data.CacheEntry
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.URI

class WalletAwareDocumentLoaderTest {

    private fun jsonDoc(content: String): JsonDocument {
        return JsonDocument.of(content.byteInputStream())
    }

    private fun mockDelegate(returned: JsonDocument): DocumentLoader {
        val mock = mockk<DocumentLoader>()
        every { mock.loadDocument(any(), any()) } returns returned
        return mock
    }

    @Test
    fun `cache hit - return cached document`() {
        val ttl = 10_000L
        val url = URI("https://example.com/context")

        val cachedDoc = jsonDoc("{\"cached\": true}")
        val newDoc = jsonDoc("{\"new\": true}")

        val walletCache = mutableMapOf(
            url.toString() to CacheEntry(
                cachedDoc,
                expiryTime = System.currentTimeMillis() + 5000
            )
        )

        val loader = WalletAwareDocumentLoader(
            ttlMillis = ttl,
            walletCache = walletCache,
            delegate = mockDelegate(newDoc)
        )

        val result = loader.loadDocument(url, DocumentLoaderOptions())

        assertSame(cachedDoc, result)
    }

    @Test
    fun `expired cache - fetch new document and update cache`() {
        val ttl = 10_000L
        val url = URI("https://example.com/context")

        val expiredDoc = jsonDoc("{\"expired\": true}")
        val freshDoc = jsonDoc("{\"fresh\": true}")

        val walletCache = mutableMapOf(
            url.toString() to CacheEntry(
                expiredDoc,
                expiryTime = System.currentTimeMillis() - 1000
            )
        )

        val loader = WalletAwareDocumentLoader(
            ttlMillis = ttl,
            walletCache = walletCache,
            delegate = mockDelegate(freshDoc)
        )

        val result = loader.loadDocument(url, DocumentLoaderOptions())

        assertSame(freshDoc, result)
        assertEquals(freshDoc, walletCache[url.toString()]!!.document)
    }

    @Test
    fun `cache miss - fetch and store document`() {
        val ttl = 10_000L
        val url = URI("https://example.com/context")

        val fetchedDoc = jsonDoc("{\"loaded\": true}")
        val walletCache = mutableMapOf<String, CacheEntry>()

        val loader = WalletAwareDocumentLoader(
            ttlMillis = ttl,
            walletCache = walletCache,
            delegate = mockDelegate(fetchedDoc)
        )

        val result = loader.loadDocument(url, DocumentLoaderOptions())

        assertSame(fetchedDoc, result)
        assertTrue(walletCache.containsKey(url.toString()))
        assertEquals(fetchedDoc, walletCache[url.toString()]!!.document)
    }
}

