package io.mosip.vercred.vcverifier.response

data class VerificationResult(
    var verificationStatus: Boolean,
    var verificationMessage: String = "",
    var verificationErrorCode: String

)