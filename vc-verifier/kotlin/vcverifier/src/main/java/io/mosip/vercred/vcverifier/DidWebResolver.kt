package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidDocumentNotFound
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.DidResolutionFailed
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.networkManager.HTTP_METHOD
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient.Companion.sendHTTPRequest
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

class DidWebResolver(private val didUrl: String) {
    companion object {
        private const val PCT_ENCODED = "(?:%[0-9a-fA-F]{2})"
        private const val ID_CHAR = "(?:[a-zA-Z0-9._-]|$PCT_ENCODED)"
        private const val METHOD = "([a-z0-9]+)"
        private const val METHOD_ID = "((?:$ID_CHAR*:)*($ID_CHAR+))"
        private const val PARAM_CHAR = "[a-zA-Z0-9_.:%-]"
        private const val PARAM = ";$PARAM_CHAR+=$PARAM_CHAR*"
        private const val PARAMS = "(($PARAM)*)"
        private const val PATH = "(/[^#?]*)?"
        private const val QUERY = "([?][^#]*)?"
        private const val FRAGMENT = "(#.*)?"
        private val DID_MATCHER = "^did:$METHOD:$METHOD_ID$PARAMS$PATH$QUERY$FRAGMENT$".toRegex()
        private const val DOC_PATH = "/did.json"
        private const val WELL_KNOWN_PATH = ".well-known"
    }

    fun resolve(): Map<String, Any> {
        val parsedDid = parseDidUrl()
        try {
            val url = constructDIDUrl(parsedDid)
            return sendHTTPRequest(url, HTTP_METHOD.GET)
                ?: throw DidDocumentNotFound("Did document could not be fetched")
        } catch (e: Exception) {
            throw DidResolutionFailed(e.message)
        }
    }

    private fun constructDIDUrl(parsedDid: ParsedDID): String {
        val idComponents = parsedDid.id.split(":").map { it }
        val baseDomain = idComponents.first()
        val path = idComponents.drop(1).joinToString("/")
        val urlPath = if (path.isEmpty()) {
            WELL_KNOWN_PATH + DOC_PATH
        } else {
            path + DOC_PATH
        }

        return "https://$baseDomain/$urlPath"
    }

    private fun parseDidUrl(): ParsedDID {
        val matchResult = DID_MATCHER.find(didUrl) ?: throw UnsupportedDidUrl()
        val sections = matchResult.groupValues

        if (sections[1] != "web") throw UnsupportedDidUrl()

        return sections.let {
            ParsedDID(
                did = "did:${it[1]}:${it[2]}",
                method = it[1],
                id = it[2],
                didUrl = didUrl
            ).apply {
                if (it[4].isNotEmpty()) {
                    params = it[4].substring(1)
                        .split(";")
                        .filter { param -> param.isNotEmpty() }
                        .associate { param ->
                            val kv = param.split("=")
                            kv[0] to (kv.getOrNull(1) ?: "")
                        }
                }

                if (it[6].isNotEmpty()) path = it[6]
                if (it[7].isNotEmpty()) query = it[7].substring(1)
                if (it[8].isNotEmpty()) fragment = it[8].substring(1)
            }
        }
    }

    data class ParsedDID(
        val did: String,
        val method: String,
        val id: String,
        val didUrl: String,
        var params: Map<String, String>? = null,
        var path: String? = null,
        var query: String? = null,
        var fragment: String? = null
    )
}