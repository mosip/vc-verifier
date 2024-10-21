export const Fields = {
    ISSUER : "issuer",
    CREDENTIAL_SUBJECT : "credentialSubject",
    PROOF : "proof",
    TYPE : "type",
    CONTEXT : "@context",
    ISSUANCE_DATE : "issuanceDate",
    EXPIRATION_DATE : "expirationDate",
    ID : "id",
    JWS : "jws",

    VALID_FROM : "validFrom",
    VALID_UNTIL : "validUntil",

    CREDENTIAL_STATUS : "credentialStatus",
    EVIDENCE : "evidence",
    TERMS_OF_USE : "termsOfUse",
    REFRESH_SERVICE : "refreshService",
    CREDENTIAL_SCHEMA : "credentialSchema",
    NAME : "name",
    DESCRIPTION : "description",
    LANGUAGE : "language",
    VALUE : "value"
}

export const ContextUrls = {
    CREDENTIALS_CONTEXT_V1_URL : "https://www.w3.org/2018/credentials/v1",
    CREDENTIALS_CONTEXT_V2_URL : "https://www.w3.org/ns/credentials/v2",
}
const VALIDATION_ERROR = "Validation Error: "

export const Errors = {
     ERROR_MISSING_REQUIRED_FIELDS : `${VALIDATION_ERROR}Missing required field: `,
     ERROR_EMPTY_VC_JSON : `${VALIDATION_ERROR}Input VC JSON string is null or empty.`,
     ERROR_CONTEXT_FIRST_LINE : `${ContextUrls.CREDENTIALS_CONTEXT_V1_URL} or ${ContextUrls.CREDENTIALS_CONTEXT_V2_URL} needs to be first in the list of contexts.`,
     ERROR_ISSUANCE_DATE_INVALID : `${VALIDATION_ERROR}issuanceDate is not valid.`,
     ERROR_EXPIRATION_DATE_INVALID : `${VALIDATION_ERROR}expirationDate is not valid.`,
     ERROR_VALID_FROM_INVALID : `${VALIDATION_ERROR}validFrom is not valid.`,
     ERROR_VALID_UNTIL_INVALID : `${VALIDATION_ERROR}validUntil is not valid.`,
     ERROR_TYPE_VERIFIABLE_CREDENTIAL : `${VALIDATION_ERROR}type must include VerifiableCredential.`,
     ERROR_INVALID_URI : `${VALIDATION_ERROR}Invalid URI: `,
     ERROR_INVALID_FIELD : `${VALIDATION_ERROR}Invalid Field: `,
     ERROR_VC_EXPIRED : `${VALIDATION_ERROR}VC is expired`,
     EXCEPTION_DURING_VALIDATION : `Unknown Exception during Validation: `,
     ERROR_ALGORITHM_NOT_SUPPORTED : `${VALIDATION_ERROR}Algorithm used in the proof is not matching with supported algorithms`,
     ERROR_PROOF_TYPE_NOT_SUPPORTED : `${VALIDATION_ERROR}Proof Type is not matching with supported types`,

     ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE : `${VALIDATION_ERROR}The current date time is before the issuanceDate`,
     ERROR_CURRENT_DATE_BEFORE_VALID_FROM : `${VALIDATION_ERROR}The current date time is before the issuanceDate`,

     ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT : `${VALIDATION_ERROR}credentialSubject must be a non-null object or array of objects.`,

     ERROR_NAME : `${VALIDATION_ERROR}name should be string or array of Language Object`,
     ERROR_DESCRIPTION : `${VALIDATION_ERROR}description should be string or array of Language Object`,

    SIGNATURE_VERIFICATION_FAILED :"Signature Verification Failed"
}


export const VERIFIABLE_CREDENTIAL = "VerifiableCredential"
