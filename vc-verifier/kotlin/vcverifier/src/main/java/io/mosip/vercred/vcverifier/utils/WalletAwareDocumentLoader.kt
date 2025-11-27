import foundation.identity.jsonld.ConfigurableDocumentLoader
import com.apicatalog.jsonld.document.Document
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.loader.DocumentLoaderOptions
import io.mosip.vercred.vcverifier.data.CacheEntry
import java.net.URI

class WalletAwareDocumentLoader(
    private val ttlMillis: Long,
    private val walletCache: MutableMap<String, CacheEntry>
) : ConfigurableDocumentLoader() {
    override fun loadDocument(url: URI, options: DocumentLoaderOptions): Document {
        val now = System.currentTimeMillis()
        val expiryTime = now + ttlMillis
        val urlStr = url.toString()

        walletCache[urlStr]?.let { cachedEntry ->
            if(cachedEntry.expiryTime > now) {
                return cachedEntry.document
            }
            else {
                walletCache.remove(urlStr)
            }
        }

        val fetched = super.loadDocument(url, options)

        if (fetched is JsonDocument) {
            walletCache[urlStr] = CacheEntry(
                document = fetched,
                expiryTime = expiryTime
            )
        }
        return fetched
    }
}
