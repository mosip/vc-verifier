package io.mosip.vercred.vcverifier.utils


import com.apicatalog.jsonld.document.Document
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.loader.DocumentLoader
import com.apicatalog.jsonld.loader.DocumentLoaderOptions
import io.mosip.vercred.vcverifier.data.CacheEntry
import java.net.URI

class WalletAwareDocumentLoader(
    private val ttlMillis: Long,
    private val walletCache: MutableMap<String, CacheEntry>,
    private val delegate: DocumentLoader
) : DocumentLoader {

    override fun loadDocument(url: URI, options: DocumentLoaderOptions): Document {
        val now = System.currentTimeMillis()
        val urlStr = url.toString()

        walletCache[urlStr]?.let { entry ->
            if (entry.expiryTime > now) return entry.document
            walletCache.remove(urlStr)
        }

        val fetched = delegate.loadDocument(url, options)

        if (fetched is JsonDocument) {
            walletCache[urlStr] = CacheEntry(
                document = fetched,
                expiryTime = now + ttlMillis
            )
        }

        return fetched
    }
}

