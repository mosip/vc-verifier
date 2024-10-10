package io.mosip.vercred.vcverifier.data

data class VerificationResult(
    var verificationStatus: Boolean,
    var verificationErrorMessage: String = ""

)