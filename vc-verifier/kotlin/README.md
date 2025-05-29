## **Vc Verifier**

### supported VC formats

- ldp_vc
- mso_mdoc 
  - Limitations: Validation of Document Signer certificate is not performed. This validation helps in establishing trust with issuing entity for the verification of authenticity and integrity of document.

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

**LDP VC Error Codes**

| Field                     | Error Code                                  |
|---------------------------|---------------------------------------------|
| credential                | ERR_EMPTY_VC                                |
| context                   | ERR_MISSING_CONTEXT                         |
|                           | ERR_INVALID_CONTEXT                         |
| type                      | ERR_MISSING_TYPE                            |
|                           | ERR_INVALID_TYPE                            |
| id                        | ERR_INVALID_ID                              |
| credentialSubject         | ERR_MISSING_CREDENTIALSUBJECT              |
|                           | ERR_INVALID_CREDENTIALSUBJECT              |
| issuer                    | ERR_MISSING_ISSUER                         |
|                           | ERR_INVALID_ISSUER                         |
| proof                     | ERR_MISSING_PROOF                           |
|                           | ERR_MISSING_PROOF_TYPE                      |
|                           | ERR_INVALID_PROOF_TYPE                      |
|                           | ERR_INVALID_ALGORITHM                       |
| issuanceDate              | ERR_MISSING_ISSUANCEDATE                   |
|                           | ERR_INVALID_ISSUANCEDATE                   |
|                           | ERR_ISSUANCE_DATE_IS_FUTURE_DATE           |
| expirationDate            | ERR_INVALID_EXPIRATIONDATE                  |
|                           | ERR_VC_EXPIRED                             |
| validFrom                 | ERR_INVALID_VALIDFROM                       |
|                           | ERR_CURRENT_DATE_BEFORE_VALID_FROM    |
| validUntil                | ERR_INVALID_VALIDUNTIL                      |
|                           | ERR_VC_EXPIRED                             |
| name                      | ERR_INVALID_NAME                            |
| description               | ERR_INVALID_DESCRIPTION                     |
| credentialStatus          | ERR_MISSING_CREDENTIALSTATUS                |
|                           | ERR_INVALID_CREDENTIALSTATUS                |
| evidence                  | ERR_MISSING_EVIDENCE                       |
|                           | ERR_INVALID_EVIDENCE                       |
| termsOfUse                | ERR_MISSING_TERMSOFUSE_TYPE                |
| refreshService            | ERR_MISSING_REFRESHSERVICE_TYPE            |
|                           | ERR_MISSING_REFRESHSERVICE_ID              |
|                           | ERR_INVALID_REFRESHSERVICE_ID              |
| credentialSchema          | ERR_MISSING_CREDENTIALSCHEMA_TYPE          |
|                           | ERR_MISSING_CREDENTIALSCHEMA_ID            |
|                           | ERR_INVALID_CREDENTIALSCHEMA_ID            |


** Mdoc Format VC Error Codes **

| Field            | Error Code           |
|------------------|----------------------|
| validFrom        | ERR_INVALID_DATE_MSO |
| validUntil       | ERR_INVALID_DATE_MSO  |
| Other Exceptions | ERR_GENERIC     |

For other unknown  exceptions, error code will be `ERR_GENERIC`

### Verify the VC Signature
-  Once Validation is completed, Library verifies the signature with method `verify(credential, format)` which accepts credential and format.
- format can `mso_mdoc` or `ldp_vc`
- credential will be VC Json String.

##### Verification Result on Success
- On Verification success, result will returned as,
```
{
    verificationStatus : true
    verificationMessage : "" or "VC is Expired"(for Expiration scenario)
    verificationErrorCode: ""
}
```

Note: Vc Expiration scenario is considered as Valid.

##### Verification Result on Failure
- On Verification failure, result will returned as,
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

### Supported DID Methods

- `did:key`
- `did:jwk`

### Verify the VP Signature
-  We can verify the Verifiable Presentation using the method `PresentationVerifier().verify(presentation)` which accepts verifiable presentation.
- presentation will be VP Json String.

##### Verification Result on Success
- On Verification success, result will returned as,
```
{
    verificationStatus : true
    verificationMessage : "" 
    verificationErrorCode: ""
}
```

##### Verification Result on Failure
- On Verification failure, result will returned as,
```
{
    verificationStatus : false
    verificationMessage : <Error Message>
    verificationErrorCode: <ERROR_CODE>
}
```

### Reference:
[Data Model 1.1](https://www.w3.org/TR/vc-data-model-1.1/)
[Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)