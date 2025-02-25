package io.mosip.vercred.vcverifier.exception

sealed class DidResolverExceptions {
    class UnsupportedDidUrl :
        BaseUncheckedException("Given did url is not supported")

    class DidDocumentNotFound(message: String?) :
        BaseUncheckedException(message)

    class DidResolutionFailed(message: String?) :
        BaseUncheckedException(message)
}