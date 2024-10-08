package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.CredentialsValidator.Companion.CREDENTIALS_CONTEXT_V1_URL

object Constants {
    const val CREDENTIAL = "credential"
    const val ISSUER = "issuer"
    const val CREDENTIAL_SUBJECT = "credentialSubject"
    const val PROOF = "proof"
    const val TYPE = "type"
    const val CONTEXT = "@context"
    const val ISSUANCE_DATE = "issuanceDate"
    const val EXPIRATION_DATE = "expirationDate"
    const val ID = "id"

    const val ERROR_MISSING_REQUIRED_FIELDS = "Missing required field: "
    const val ERROR_EMPTY_VC_JSON = "Input VC JSON string is null or empty."
    const val ERROR_CONTEXT_FIRST_LINE = "$CREDENTIALS_CONTEXT_V1_URL needs to be first in the list of contexts."
    const val ERROR_ISSUANCE_DATE_INVALID = "issuanceDate is not valid."
    const val ERROR_EXPIRATION_DATE_INVALID = "expirationDate is not valid."
    const val ERROR_TYPE_VERIFIABLE_CREDENTIAL = "type must include `VerifiableCredential`."
}