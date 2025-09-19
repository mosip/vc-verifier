package io.mosip.vercred.vcverifier.signature

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256K_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.signature.impl.PS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.RS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ES256KSignatureVerifierImpl

class SignatureFactory {

    fun get(signatureAlgorithm: String) : SignatureVerifier {
        return when {
            JWS_PS256_SIGN_ALGO_CONST == signatureAlgorithm -> PS256SignatureVerifierImpl()
            JWS_RS256_SIGN_ALGO_CONST == signatureAlgorithm -> RS256SignatureVerifierImpl()
            JWS_EDDSA_SIGN_ALGO_CONST == signatureAlgorithm -> ED25519SignatureVerifierImpl()
            JWS_ES256K_SIGN_ALGO_CONST == signatureAlgorithm -> ES256KSignatureVerifierImpl()
            JWS_ES256_SIGN_ALGO_CONST == signatureAlgorithm -> ES256KSignatureVerifierImpl()
            else -> throw SignatureNotSupportedException("Unsupported jws signature algorithm")
        }
    }
}