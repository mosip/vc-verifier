package io.mosip.vercred.vcverifier.response

data class ValidationStatus(
    val validationMessage: String,
    val validationErrorCode: String
)