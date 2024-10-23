package io.mosip.vercred.vcverifier.data

data class VerificationResult(
    var verificationStatus: Boolean,
    var verificationMessage: String = ""

)


enum class DATA_MODEL {
    DATA_MODEL_1_1,
    DATA_MODEL_2_0,
    UNSUPPORTED
}