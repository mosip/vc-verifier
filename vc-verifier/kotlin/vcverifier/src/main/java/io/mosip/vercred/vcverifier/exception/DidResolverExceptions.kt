package io.mosip.vercred.vcverifier.exception

sealed class DidResolverExceptions {
    class UnsupportedDidUrl(message: String? = null) :
        BaseUncheckedException(message ?: "Given did url is not supported")

    class DidDocumentNotFound(message: String?) :
        BaseUncheckedException(message)

    class DidResolutionFailed(message: String?) :
        BaseUncheckedException(message)
}