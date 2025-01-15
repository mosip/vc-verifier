
# vc-verifier

**VC Verifier Library** is a comprehensive Java/Kotlin library designed to enable the validation and verification of **Verifiable Credentials (VCs)**, a crucial component in modern decentralized identity systems. This library provides a robust mechanism for verifying the authenticity and integrity of VCs, ensuring that the claims made within the credential are both valid and trustworthy.

#### Key Features:

-   **VC Validation**: The library validates the structure, signatures, and expiration of Verifiable Credentials to ensure they conform to the W3C VC standards.
-   **Cryptographic Signature Verification**: Supports the verification of cryptographic signatures using public keys, including EdDSA, RSA, and other supported algorithms, ensuring the integrity of the credential.
-   **Compatibility with Various Data Models**: It supports multiple VC data models (e.g., VC 1.1, VC 2.0), ensuring compatibility across various decentralized identity systems.

#### Supported VC Formats:
-   ldp_vc
-   mso_mdoc

#### Supported Algorithms:
-   PS256
-   RS256
-   EdDSA (Ed25519)

#### Proof Types Supported:
-   RsaSignature2018
-   Ed25519Signature2018
-   Ed25519Signature2020

#### Project Structure

`io.mosip.vercred.vcverifier`
- **constants**
- **credentialverifier**
    - `types`
    - `validator`
    - `verifier`
- **data**
- **exception**
- **signature**
    - `impl`
- **utils**
- **CredentialVerifier.kt**

#### Package Description

- **constants** - All Validator and Verifier constants are declared in this package.
- **credentialverifier** - CredentialFactory for different credential formats are declared in this package. It also consists of classes for different credential formats.
- **data** - It has data classes for Validation Status and Verification Result.
- **exception** - Custom exceptions are defined in this package.
- **signature** - Interface and Implementations for multiple Signature Verification are available in this package.
- **utils** - It helper classes and methods that provide reusable and general-purpose functionalities across the project.
- **CredentialVerifier.kt** - The `CredentialVerifier.kt` file serves as the main entry point to the VC Verifier Library. This class provides the primary interface for interacting with the library and encapsulates all the core functionalities related to validating and verifying Verifiable Credentials (VCs).




#### References:

[Data Model 1.1]( https://www.w3.org/TR/vc-data-model-1.1/)
[Data Model 2.0]( https://www.w3.org/TR/vc-data-model-2.0/)