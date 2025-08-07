## Support of credential format vc+sd-jwt

This document provides a comprehensive overview of verifying `vc+sd-jwt` Verifiable Credentials (VCs).

### Public key resolution support
X.509 Certificates - Retrieves Issuer's public key using `x5c header parameter` in SD-JWT header.
DID Document - Retrieves Issuer's public key using `kid` in SD-JWT header.

### Steps Involved
1. Add enum value `SD_JWT_VC("vc+sd-jwt")` in `CredentialFormat`
2. Create a new class `SdJwtVerifiableCredential` that implements `VerifiableCredential` interface. This class will be used to validate and verify the `vc+sd-jwt` format credentials.
   - `validate` method will be used to validate the credential format and its claims.
   - `verify` method will be used to verify the credential signature and disclosures.
   - `isRevoked` method will return false as `vc+sd-jwt` does not support revocation.
3. Create a class `SdJwtValidator` to validate the credential format and claims.
   -  method `validate` to validate the credential format, claims
4. Create a class `SdJwtVerifier` to verify the credential format and claims.
   - method `verify` to verify credential Cryptographic Signature
   - It will verify the disclosures using Cryptographic Hash Verification. (SHA-256 if `_sd_alg` is not specified, otherwise use the algorithm specified in `_sd_alg` claim)
5. Implement the `validate` method in `SdJwtVerifiableCredential` class to perform the following checks:
   - Validate the credential format is `vc+sd-jwt`.
   - Validate the credential claims against the issuer metadata.
   - Ensure that the credential contains required claims as per the issuer's configuration.
   - Check if the credential is expired or not.
   - Ensure that the credential is not revoked (though `vc+sd-jwt` does not support revocation, this check can be a placeholder for future use).
6. Implement the `verify` method in `SdJwtVerifiableCredential` class to perform the following checks:
   - Confirm the credential is not tampered (Cryptographic Signature Verification).
   - Disclosure Verification to confirm sd claims are not tampered (Cryptographic Hash Verification).
7. Implement the `CredentialVerifierFactory` to create an instance of `SdJwtVerifiableCredential` when the credential format is `vc+sd-jwt`.


###  Sequence diagram - validate and verify `vc+sd-jwt` credential format VC

```mermaid
sequenceDiagram
   Wallet->>CredentialsVerifier: verify credential<br/>verify(credential: "jwt-string", credentialFormat: "vc+sd-jwt")
   CredentialsVerifier->>CredentialVerifierFactory: Create instance of VerifiableCredential based on format vc+sd-jwt
   CredentialVerifierFactory->>SdJwtVerifiableCredential: Create SdJwtVerifiableCredential instance
   CredentialsVerifier->>SdJwtVerifiableCredential: Validate sd-jwt Credential
   SdJwtVerifiableCredential->>SdJwtValidator: Validate sd-jwt Credential
   SdJwtValidator-->>SdJwtVerifiableCredential: Return validation result
   SdJwtVerifiableCredential-->>CredentialsVerifier: Return validation result
   
   alt Credential is Invalid
      CredentialsVerifier-->>Wallet: Return Verification Result as False with validation error
   else Credential is Valid
      CredentialsVerifier->>SdJwtVerifiableCredential: Verify sd-jwt Credential
      SdJwtVerifiableCredential->>SdJwtVerifier: Verify sd-jwt Credential
      SdJwtVerifier-->>SdJwtVerifiableCredential: Return Verification Result
      SdJwtVerifiableCredential-->>CredentialsVerifier: Return verification result
      
      alt Verification Failed
         CredentialsVerifier-->>Wallet: Return Verification Result as False with error
      else Verification Success
         CredentialsVerifier->>SdJwtVerifiableCredential: Check revocation status
         SdJwtVerifiableCredential-->>CredentialsVerifier: Return false as it's not supported
         CredentialsVerifier-->>Wallet: Return Verification Result as True
      end
   end
```

###  Sequence diagram - validation process for `vc+sd-jwt` credential format VC

```mermaid
sequenceDiagram

    SdJwtVerifiableCredential->>SdJwtValidator: Validate sd-jwt Credential
    SdJwtValidator->>SdJwtValidator: Parse JWT
    SdJwtValidator->>SdJwtValidator: Validate Header
    Note over SdJwtValidator: typ header must be present and<br/>it's value must be `vc+sd-jwt`
    Note over SdJwtValidator: alg header must be present
    SdJwtValidator->>SdJwtValidator: Validate Payload/Claims
    Note over SdJwtValidator: vct must be present and<br/>value MUST be a case-sensitive StringOrURI
    Note over SdJwtValidator: iss is optional. If present, must be an issuer
    Note over SdJwtValidator: nbf is optional. If present, not before time cannot be in future
    Note over SdJwtValidator: exp is optional. If present, expired time cannot be in past
    Note over SdJwtValidator: cnf is optional. Must if cryptographic Key Binding is to be supported
    Note over SdJwtValidator: iat is optional. If present, issued at time cannot be in future
    Note over SdJwtValidator: _sd_alg is optional. If present, must be a valid algorithm(e.g., sha-256, sha-384, sha-512)
    Note over SdJwtValidator: if `_sd` present, value MUST be an array of digests
    Note over SdJwtValidator: digest length check based on hash algo  `sha-256` - 32, `sha-384` to 48, `sha-512` to 64
    alt if Disclosures present
        SdJwtValidator->>SdJwtValidator: Validate Disclosures
        loop For each disclosure
            SdJwtValidator->>SdJwtValidator: Create digest with sha-256 if `_sd_alg` is not specified and<br/>Base64URL Encode
        end
       SdJwtValidator->>SdJwtValidator: digest must match the hash available in `_sd` array inside payload <br/>or `_sd` available in claims
        alt If any digest does not match or missing
            SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as False with error
        else All digests match
            Note over SdJwtValidator: after base64 decoding, json object should be of size 2(salt and value if it's array) or 3(salt, key, value if object)
            Note over SdJwtValidator: disclosure claim name should exist once
            Note over SdJwtValidator: disclosure claim name should not conflict with claim name in payload
           alt If any validation fails
              SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as False with error
           else Validiation Success
              SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as True
           end
        end
    else If Disclosures not present
        alt If any validation fails
            SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as False with error
        else Validiation Success
           SdJwtValidator-->>SdJwtVerifiableCredential: Return Validation Result as True
        end
    end
```   

###  Sequence diagram - verification process for `vc+sd-jwt` credential format VC

```mermaid
sequenceDiagram
   
    SdJwtVerifiableCredential->>SdJwtVerifier: Verify sd-jwt Credential
    SdJwtVerifier->>SdJwtVerifier: Separate JWT and disclosures
    alt Invalid JWT
       SdJwtVerifier-->>SdJwtVerifiableCredential: Return Verification Result as False with error
    else Valid JWT
       SdJwtVerifier->>SdJwtVerifier: Parse JWT
       SdJwtVerifier->>SdJwtVerifier: Extract JWT Header
       SdJwtVerifier->>SdJwtVerifier: Extract x5c Certificate
       SdJwtVerifier->>SdJwtVerifier: Extract Algorithm
       SdJwtVerifier->>SdJwtVerifier: Extract Public Key
       SdJwtVerifier->>SdJwtVerifier: Verify Signature
       alt Signature Invalid
          SdJwtVerifier-->>SdJwtVerifiableCredential: Return Verification Result as False with error
       else Signature Valid
          SdJwtVerifier-->>SdJwtVerifiableCredential: Return Verification Result as True
       end
    end
```