package io.mosip.vercred.vcverifier.constants

import io.mosip.vercred.vcverifier.CredentialsValidator.Companion.CREDENTIALS_CONTEXT_V1_URL

object CredentialValidatorConstants {
    const val CREDENTIAL = "credential"
    const val ISSUER = "issuer"
    const val CREDENTIAL_SUBJECT = "credentialSubject"
    const val PROOF = "proof"
    const val TYPE = "type"
    const val CONTEXT = "@context"
    const val ISSUANCE_DATE = "issuanceDate"
    const val EXPIRATION_DATE = "expirationDate"
    const val ID = "id"
    const val JWS = "jws"

    private const val VALIDATION_ERROR = "Validation Error: "
    const val ERROR_MISSING_REQUIRED_FIELDS = "${VALIDATION_ERROR}Missing required field: "
    const val ERROR_EMPTY_VC_JSON = "${VALIDATION_ERROR}Input VC JSON string is null or empty."
    const val ERROR_CONTEXT_FIRST_LINE = "${VALIDATION_ERROR}$CREDENTIALS_CONTEXT_V1_URL needs to be first in the list of contexts."
    const val ERROR_ISSUANCE_DATE_INVALID = "${VALIDATION_ERROR}issuanceDate is not valid."
    const val ERROR_EXPIRATION_DATE_INVALID = "${VALIDATION_ERROR}expirationDate is not valid."
    const val ERROR_TYPE_VERIFIABLE_CREDENTIAL = "${VALIDATION_ERROR}type must include `VerifiableCredential`."
    const val ERROR_INVALID_URI = "${VALIDATION_ERROR}Invalid URI."
    const val ERROR_VC_EXPIRED = "VC is expired"
    const val EXCEPTION_DURING_VALIDATION = "${VALIDATION_ERROR}Exception during Validation: "
    const val ERROR_ALGORITHM_NOT_SUPPORTED = "${VALIDATION_ERROR}Algorithm used in the proof is not matching with supported algorithms"
    const val ERROR_PROOF_TYPE_NOT_SUPPORTED = "${VALIDATION_ERROR}Proof Type is not matching with supported types"


    val DATE_REGEX = Regex(
        """^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(Z|(\+|-)([01][0-9]|2[0-3]):([0-5][0-9]))$""",
        RegexOption.IGNORE_CASE
    )


    val ALGORITHMS_SUPPORTED = listOf(
        "PS256",
        "RS256"
    )

    val PROOF_TYPES_SUPPORTED = listOf(
        "RsaSignature2018"
    )
}