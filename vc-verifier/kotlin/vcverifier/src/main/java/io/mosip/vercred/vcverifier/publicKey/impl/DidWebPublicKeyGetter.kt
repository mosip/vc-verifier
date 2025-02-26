package io.mosip.vercred.vcverifier.publicKey.impl

import io.mosip.vercred.vcverifier.DidWebResolver
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFICATION_METHOD
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetter
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPemPublicKey
import io.mosip.vercred.vcverifier.publicKey.getPublicKeyObjectFromPublicKeyMultibase
import io.mosip.vercred.vcverifier.publicKey.isPemPublicKey
import io.mosip.vercred.vcverifier.publicKey.isPublicKeyMultibase
import java.net.URI
import java.security.PublicKey
import java.util.logging.Logger

class DidWebPublicKeyGetter: PublicKeyGetter {

    private val logger = Logger.getLogger(DidWebPublicKeyGetter::class.java.name)

    override fun get(verificationMethod: URI): PublicKey {
        try {
            val didDocument = DidWebResolver(verificationMethod.toString()).resolve()
            didDocument.let{
                val publicKeyStr = getKeyValue(it, PUBLIC_KEY_MULTIBASE)
                val keyType = getKeyValue(it,KEY_TYPE)
                return when {
                    isPemPublicKey(publicKeyStr) -> getPublicKeyObjectFromPemPublicKey(publicKeyStr, keyType)
                    isPublicKeyMultibase(publicKeyStr) -> getPublicKeyObjectFromPublicKeyMultibase(publicKeyStr, keyType)
                    else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
                }
            }
        } catch (e: Exception) {
            logger.severe("Error fetching public key string $e")
            throw PublicKeyNotFoundException(e.message)
        }
    }

    //TODO: match the key instead of taking the 0th index data
    private fun getKeyValue(responseObjectNode: Map<String, Any>, key: String): String {
        val verificationMethodList = responseObjectNode[VERIFICATION_METHOD] as ArrayList<Map<String, Any>>
        return verificationMethodList[0][key].toString()
    }
}