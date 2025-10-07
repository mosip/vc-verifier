## Support for IETF SD-JWT KB JWT Verification

This document provides a comprehensive overview of verifying KB JWT for `vc+sd-jwt` and `dc+sd-jwt` Verifiable Presentation (VP).

### Cryptographic Key Binding Support
- `cnf` available in VC can either be `jwk`(JSON Web Key) or `kid`.
  - If `jwk` is present, it will contain the public key of the holder.
  - If `kid` is present, it will contain the reference to the public key of the holder.
    - Currently, only `did` is supported for `kid` in `cnf`.


### Steps Involved for Validation/Verification

1. Validate `kb+jwt`
   - Parse JWT - It should be valid JWT with 3 parts - header, payload and signature 
   - Validate Header
     - `typ`is mandatory. Must be present and value MUST be `kb+jwt`
     - `alg` is mandatory. Must be present and value MUST be a valid algorithm(e.g., PS256, RS256, EdDSA, ES256K, ES256)
   - Validate Payload
     - `aud` is mandatory. Must be present and value MUST be a valid URI
     - `nonce` is mandatory. Must be present and value MUST be a String
     - `iat` is mandatory. Must be present and value MUST be a number containing a NumericDate value
     - `sd_hash` is mandatory. Must be present and value MUST be base64url-encoded hash value
       - digest length check based on hash algo  `sha-256` - 32 bytes, `sha-384` to 48 bytes, `sha-512` to 64 bytes
   - Fetch Holder's Public Key from SD JWT Payload
     - `cnf` is mandatory. Must be present and value MUST be either `jwk` or `kid`
    - Verify Signature
      - Use the public key from `jwk` or `kid` in `cnf` to verify the signature of KB JWT
      - Use the algorithm specified in `alg` header to verify the signature
2. If there is any error in any of the steps, return validation error



###  Sequence diagram - validate and verify `kb+jwt`


```mermaid
sequenceDiagram

    SdJwtVerifiableCredential->>SdJwtValidator: Validate sd-jwt Credential with kb+jwt
    SdJwtValidator->>SdJwtValidator: Validate KB JWT by checking if it is well-formed
    alt Invalid JWT
        SdJwtValidator-->>SdJwtVerifiableCredential: Return Verification Result as False with error
    else Valid JWT
        SdJwtValidator->>SdJwtValidator: Parse KB JWT
        SdJwtValidator->>SdJwtValidator: Validate Header
        Note over SdJwtValidator: typ header must be present and<br/>it's value must be `kb+jwt`
        Note over SdJwtValidator: alg header must be present
        alt Validation Fails
            SdJwtValidator-->>SdJwtVerifiableCredential: Return Verification Result as False with error
        else Validation Success
            SdJwtValidator->>SdJwtValidator: Validate KB JWT Payload
            Note over SdJwtValidator: aud must be present and<br/>value must be a valid URI
            Note over SdJwtValidator: nonce must be present and<br/>value must be a String
            Note over SdJwtValidator: iat must be present and<br/>value must be a number containing a NumericDate value
            Note over SdJwtValidator: sd_hash must be present and<br/>value must be base64url-encoded hash value
            SdJwtValidator->>SdJwtValidator: Fetch Holder's Public Key from SD JWT Payload
            Note over SdJwtValidator: cnf must be present and<br/>value must be either jwk or kid
            alt Validation Fails
                SdJwtValidator-->>SdJwtVerifiableCredential: Return Verification Result as False with error
            else Validation Success
                SdJwtValidator->>SdJwtValidator: Verify Signature
                Note over SdJwtValidator: Extract Public Key from cnf
                Note over SdJwtValidator: Extract alg from header
                alt Signature Valid
                    SdJwtValidator-->>SdJwtVerifiableCredential: Return Verification Result as True
                else Signature Invalid
                    SdJwtValidator-->>SdJwtVerifiableCredential: Return Verification Result as False with error
                end
            end
        end
    end
```