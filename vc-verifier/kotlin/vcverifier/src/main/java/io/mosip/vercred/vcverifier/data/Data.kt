package io.mosip.vercred.vcverifier.data

data class VerificationResult(
    var verificationStatus: Boolean,
    var verificationMessage: String = "",
    var verificationErrorCode: String

)

data class PresentationVerificationResult(
    var proofVerificationStatus: Boolean,
    var vcResults: List<VCResult>
)

data class VCResult(
    val vc: String,
    val status: VerificationStatus
)


enum class VerificationStatus {
    SUCCESS,
    EXPIRED,
    INVALID
}

enum class DATA_MODEL {
    DATA_MODEL_1_1,
    DATA_MODEL_2_0,
    UNSUPPORTED
}

data class ValidationStatus(
    val validationMessage: String,
    val validationErrorCode: String
)