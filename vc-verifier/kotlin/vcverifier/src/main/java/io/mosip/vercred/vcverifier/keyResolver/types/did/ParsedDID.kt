package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.mosip.vercred.vcverifier.constants.DidMethod

data class ParsedDID(
        val did: String,
        val method: DidMethod,
        val id: String,
        val didUrl: String,
        var params: Map<String, String>? = null,
        var path: String? = null,
        var query: String? = null,
        var fragment: String? = null
)