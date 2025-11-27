package io.mosip.vercred.vcverifier.utils

import WalletAwareDocumentLoader
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.loader.DocumentLoader
import com.apicatalog.jsonld.loader.DocumentLoaderOptions
import foundation.identity.jsonld.ConfigurableDocumentLoader
import io.mosip.vercred.vcverifier.data.CacheEntry
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.URI

class WalletAwareDocumentLoaderTest {


    private fun jsonDoc(content: String): JsonDocument {
        return JsonDocument.of(content.byteInputStream())
    }

    class FakeDelegateLoader(private val returned: JsonDocument) : ConfigurableDocumentLoader() {
        override fun loadDocument(url: URI, options: DocumentLoaderOptions) = returned
    }


    @Test
    fun `cache hit - return cached document`() {
        val ttl = 10_000L
        val url = URI("https://example.com/context")

        val cachedDoc = jsonDoc("{\"cached\": true}")
        val newDoc = jsonDoc("{\"new\": true}")  // should NOT be used

        val walletCache = mutableMapOf(
            url.toString() to CacheEntry(
                cachedDoc,
                expiryTime = System.currentTimeMillis() + 5000  // still valid
            )
        )

        val loader = WalletAwareDocumentLoader(
            ttlMillis = ttl,
            walletCache = walletCache,
            delegate = FakeDelegateLoader(newDoc)
        )

        val result = loader.loadDocument(url, DocumentLoaderOptions())

        assertSame(cachedDoc, result)   // returned from cache
    }

    // ------------------------------------------------------------
    // TEST 2: Expired Cache -> Reload -> Update Cache
    // ------------------------------------------------------------
    @Test
    fun `expired cache - fetch new document and update cache`() {
        val ttl = 10_000L
        val url = URI("https://example.com/context")

        val expiredDoc = jsonDoc("{\"expired\": true}")
        val freshDoc = jsonDoc("{\"fresh\": true}")

        val walletCache = mutableMapOf(
            url.toString() to CacheEntry(
                expiredDoc,
                expiryTime = System.currentTimeMillis() - 2000 // EXPIRED
            )
        )

        val loader = WalletAwareDocumentLoader(
            ttlMillis = ttl,
            walletCache = walletCache,
            delegate = FakeDelegateLoader(freshDoc)
        )

        val result = loader.loadDocument(url, DocumentLoaderOptions())

        assertSame(freshDoc, result)
        assertEquals(freshDoc, walletCache[url.toString()]!!.document)
    }

    // ------------------------------------------------------------
    // TEST 3: Cache Miss -> Load -> Store in Cache
    // ------------------------------------------------------------
    @Test
    fun `cache miss - fetch and store document`() {
        val ttl = 10_000L
        val url = URI("https://example.com/context")

        val fetchedDoc = jsonDoc("{\"loaded\": true}")
        val walletCache = mutableMapOf<String, CacheEntry>()

        val loader = WalletAwareDocumentLoader(
            ttlMillis = ttl,
            walletCache = walletCache,
            delegate = FakeDelegateLoader(fetchedDoc)
        )

        val result = loader.loadDocument(url, DocumentLoaderOptions())

        assertSame(fetchedDoc, result)
        assertTrue(walletCache.containsKey(url.toString()))
        assertEquals(fetchedDoc, walletCache[url.toString()]!!.document)
    }
}
