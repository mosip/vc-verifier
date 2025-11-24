## **Vc Verifier**

### supported VC formats

- ldp_vc
- mso_mdoc 
  - Limitations: Validation of Document Signer certificate is not performed. This validation helps in establishing trust with issuing entity for the verification of authenticity and integrity of document.
- vc+sd-jwt
- dc+sd-jwt

### Validate the VC
- Validation should be done before doing actual signature verification which identifies invalid or missing fields in the earlier stage.
##### VC Context/Schema validation
- Context/Schema validation for identifying missing or invalid fields for individual fields to ensure conformance to the standards and returning appropriate error messages.
##### Proof type validation
- Checking for supported algorithm is being used if proof has JWS and check for supported proof types.
##### Expiry validation
- Expired VCs are also required in certain cases where it can be asked as a proof. For eg: Passport. As part of VC download, users should be able to download the expired VCs as well.

##### Error Codes
- Consumer can use these Error codes to handle different error scenarios based on the requirements.

Error codes mapped to fields in VC are listed below:

**ldp_vc Error Codes**

| Field                     | Error Code                              |
|---------------------------|-----------------------------------------|
| credential                | ERR_EMPTY_VC                            |
| context                   | ERR_MISSING_CONTEXT                     |
|                           | ERR_INVALID_CONTEXT                     |
| type                      | ERR_MISSING_TYPE                        |
|                           | ERR_INVALID_TYPE                        |
| id                        | ERR_INVALID_ID                          |
| credentialSubject         | ERR_MISSING_CREDENTIALSUBJECT           |
|                           | ERR_INVALID_CREDENTIALSUBJECT           |
| issuer                    | ERR_MISSING_ISSUER                      |
|                           | ERR_INVALID_ISSUER                      |
| proof                     | ERR_MISSING_PROOF                       |
|                           | ERR_MISSING_PROOF_TYPE                  |
|                           | ERR_INVALID_PROOF_TYPE                  |
|                           | ERR_INVALID_ALGORITHM                   |
| issuanceDate              | ERR_MISSING_ISSUANCEDATE                |
|                           | ERR_INVALID_ISSUANCEDATE                |
|                           | ERR_ISSUANCE_DATE_IS_FUTURE_DATE        |
| expirationDate            | ERR_INVALID_EXPIRATIONDATE              |
|                           | ERR_VC_EXPIRED                          |
| validFrom                 | ERR_INVALID_VALIDFROM                   |
|                           | ERR_CURRENT_DATE_BEFORE_VALID_FROM      |
| validUntil                | ERR_INVALID_VALIDUNTIL                  |
|                           | ERR_VC_EXPIRED                          |
| name                      | ERR_INVALID_NAME                        |
| description               | ERR_INVALID_DESCRIPTION                 |
| credentialStatus          | ERR_MISSING_CREDENTIALSTATUS            |
|                           | ERR_INVALID_CREDENTIALSTATUS            |
| evidence                  | ERR_MISSING_EVIDENCE                    |
|                           | ERR_INVALID_EVIDENCE                    |
| termsOfUse                | ERR_MISSING_TERMSOFUSE_TYPE             |
| refreshService            | ERR_MISSING_REFRESHSERVICE_TYPE         |
|                           | ERR_MISSING_REFRESHSERVICE_ID           |
|                           | ERR_INVALID_REFRESHSERVICE_ID           |
| credentialSchema          | ERR_MISSING_CREDENTIALSCHEMA_TYPE       |
|                           | ERR_MISSING_CREDENTIALSCHEMA_ID         |
|                           | ERR_INVALID_CREDENTIALSCHEMA_ID         |

For other unknown exceptions, error code will be `ERR_GENERIC`


** mso_mdoc Format VC Error Codes **

| Field            | Error Code           |
|------------------|----------------------|
| validFrom        | ERR_INVALID_DATE_MSO |
| validUntil       | ERR_INVALID_DATE_MSO |

For other unknown exceptions, error code will be `ERR_GENERIC`

** vc+sd-jwt/dc+sd-jwt Format VC Error Codes **

| Field                     | Error Code                         |
|---------------------------|------------------------------------|
| credential empty          | ERR_EMPTY_VC                       |
| JWT                       | ERR_INVALID_JWT_FORMAT             |
| alg in header             | ERR_INVALID_ALG                    |
| typ in header             | ERR_INVALID_TYP                    |
| vct in payload            | ERR_INVALID_VCT                    |
| vct in payload            | ERR_INVALID_VCT_URI                |
| iss in payload            | ERR_INVALID_ISS                    |
| _sd_alg in payload        | ERR_INVALID_SD_ALG                 |
| iat in payload            | ERR_ISSUANCE_DATE_IS_FUTURE_DATE   |
| nbf in payload            | ERR_PROCESSING_DATE_IS_FUTURE_DATE |
| exp in payload            | ERR_VC_EXPIRED                     |
| aud in payload            | ERR_INVALID_AUD                    |
| cnf in payload            | ERR_INVALID_CNF                    |
| disclosure format         | ERR_INVALID_DISCLOSURE_FORMAT      |
| disclosure json length    | ERR_INVALID_DISCLOSURE_STRUCTURE   |
| disclosure claim          | ERR_INVALID_DISCLOSURE_CLAIM_NAME  |
| disclosure hash length    | ERR_INVALID_ALG                    |
| disclosure digest empty   | ERR_INVALID_DIGEST                 |
| KB JWT                    | ERR_INVALID_KB_JWT_FORMAT          |
| KB JWT header             | ERR_INVALID_KB_JWT_HEADER          |
| KB JWT header             | ERR_INVALID_KB_JWT_HEADER          |
| alg in KB JWT header      | ERR_MISSING_KB_JWT_ALG             |
| alg in KB JWT header      | ERR_INVALID_KB_JWT_ALG             |
| typ in KB JWT header      | ERR_INVALID_KB_JWT_TYP             |
| cnf in KB JWT header      | ERR_INVALID_CNF                    |
| cnf in KB JWT header      | ERR_INVALID_CNF_TYPE               |
| cnf in KB JWT header      | ERR_INVALID_KB_SIGNATURE           |
| aud in KB JWT payload     | ERR_MISSING_AUD                    |
| nonce in KB JWT payload   | ERR_MISSING_NONCE                  |
| sd_hash in KB JWT payload | ERR_MISSING_SD_HASH                |
| iat in KB JWT payload     | ERR_MISSING_IAT                    |
| aud in KB JWT payload     | ERR_INVALID_AUD                    |
| nonce in KB JWT payload   | ERR_INVALID_NONCE                  |
| iat in KB JWT payload     | ERR_INVALID_KB_JWT_IAT             |
| sd_hash in KB JWT payload | ERR_INVALID_SD_HASH                |


For other unknown exceptions, error code will be `ERR_INVALID_UNKNOWN`

### Verify the VC Signature
- Once Validation is completed, Library verifies the signature with method `verify(credential, format)` which accepts credential and format.
- format is either `ldp_vc`, `mso_mdoc`, `vc+sd-jwt` or `dc+sd-jwt`
- credential is VC Json String.

##### Verification Result on Success
- On Verification success, result will be returned as,
```
{
    verificationStatus : true
    verificationMessage : "" or "VC is Expired"(for Expiration scenario)
    verificationErrorCode: ""
}
```

Note: Vc Expiration scenario is considered as Valid.

##### Verification Result on Failure
- On Verification failure, result will be returned as,
```
{
    verificationStatus : false
    verificationMessage : <Error Message>
    verificationErrorCode: <ERROR_CODE>
}
```
Generally the Error codes are from Validation Failure, when Verification fails Error code will be `ERR_GENERIC`

### supported VP formats

- ldp_vc

### Supported VP Proof Signatures

- Ed25519Signature2018
- Ed25519Signature2020
- JsonWebSignature2020 with Ed25519

### Supported DID Methods

- `did:web`
- `did:key`
- `did:jwk`

### Verify the VP Signature
-  We can verify the Verifiable Presentation using the method `PresentationVerifier().verify(presentation)` which accepts verifiable presentation.
- presentation will be VP Json String.

##### Verification Result on Success
- On VP Proof Verification success, result will returned as,
```
{
    "proofVerificationStatus" : "VALID",
    "vcResults": [
      {
        "vc": "string",
        "status": "success|invalid|expired"
      }
    ]
}
```

##### Verification Result on Failure
- On VP Proof Verification failure, result will be returned as,
```
{
    "proofVerificationStatus" : "INVALID",
    "vcResults": [
      {
        "vc": "string",
        "status": "success|invalid|expired"
      }
    ]
}
```

> **_NOTE:_** In the `PresentationVerifier` we are adding the entire VC as a string in the method response. We know that this is not very efficient. But in newer draft of OpenId4VP specifications the Presentation Exchange is fully removed so we rather not use the submission_requirements for giving the VC reference for response. As of now we could not find anything unique that can be referred in a vp_token VC we will be going with the approach of sending whole VC back in response.

### Reference:
- [Data Model 1.1](https://www.w3.org/TR/vc-data-model-1.1/)
- [Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [IETF SD-JWT DRAFT](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html)