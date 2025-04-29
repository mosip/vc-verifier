package io.mosip.vercred.vcverifier.credentialverifier.verifier

import foundation.identity.jsonld.JsonLDObject

interface RevocationChecker {
    fun isRevoked(vcJsonLdObject: JsonLDObject): Boolean
}
