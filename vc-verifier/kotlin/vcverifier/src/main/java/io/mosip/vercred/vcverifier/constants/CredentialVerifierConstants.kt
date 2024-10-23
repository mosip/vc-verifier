package io.mosip.vercred.vcverifier.constants


object CredentialVerifierConstants {

    const val PUBLIC_KEY_PEM = "publicKeyPem"
    const val PUBLIC_KEY_MULTIBASE = "publicKeyMultibase"
    const val VERIFICATION_METHOD = "verificationMethod"

    const val PSS_PARAM_SHA_256 = "SHA-256"
    const val PSS_PARAM_MGF1 = "MGF1"
    const val PSS_PARAM_SALT_LEN = 32
    const val PSS_PARAM_TF = 1

    const val PS256_ALGORITHM = "SHA256withRSA/PSS"
    const val RS256_ALGORITHM = "SHA256withRSA"
    const val ED25519_ALGORITHM = "Ed25519"
    const val RSA_ALGORITHM = "RSA"

    const val JWS_PS256_SIGN_ALGO_CONST = "PS256"
    const val JWS_RS256_SIGN_ALGO_CONST = "RS256"
    const val JWS_EDDSA_SIGN_ALGO_CONST = "EdDSA"

    const val RSA_SIGNATURE = "RsaSignature2018"
    const val ED25519_SIGNATURE_2018 = "Ed25519Signature2018"
    const val ED25519_SIGNATURE_2020 = "Ed25519Signature2020"

    const val EXCEPTION_DURING_VERIFICATION = "Exception during Verification: "
    const val VERIFICATION_FAILED = "Verification Failed"

    const val DER_PUBLIC_KEY_PREFIX = "302a300506032b6570032100"
}