package io.mosip.vercred.vcverifier.exception

sealed class NetworkManagerClientExceptions {
    class NetworkRequestTimeout :
        BaseUncheckedException("Connection timeout")

    class NetworkRequestFailed(error: String) :
        BaseUncheckedException("Network request failed with error response - $error")
}