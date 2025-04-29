package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256K_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetterFactory
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ES256KSignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.PS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.RS256SignatureVerifierImpl
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.util.logging.Logger


class LdpVerifier {

    private val logger = Logger.getLogger(LdpVerifier::class.java.name)

    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    private val SIGNATURE_VERIFIER: Map<String, SignatureVerifier> = mapOf(
        JWS_PS256_SIGN_ALGO_CONST to PS256SignatureVerifierImpl(),
        JWS_RS256_SIGN_ALGO_CONST to RS256SignatureVerifierImpl(),
        JWS_EDDSA_SIGN_ALGO_CONST to ED25519SignatureVerifierImpl(),
        JWS_ES256K_SIGN_ALGO_CONST to ES256KSignatureVerifierImpl()
    )

    init {
        Security.addProvider(provider);
    }

    fun verify(credential: String): Boolean {

        logger.info("Received Credentials Verification - Start")
        val confDocumentLoader: ConfigurableDocumentLoader = getConfigurableDocumentLoader()
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(credential)
        vcJsonLdObject.documentLoader = confDocumentLoader

        return try {
            val ldProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

            val canonicalizer = URDNA2015Canonicalizer()
            val canonicalHashBytes = canonicalizer.canonicalize(ldProof, vcJsonLdObject)

            val verificationMethod = ldProof.verificationMethod
            val publicKeyObj = PublicKeyGetterFactory().get(verificationMethod)

            if (!ldProof.jws.isNullOrEmpty()) {
                val signJWS: String = ldProof.jws
                val jwsObject = JWSObject.parse(signJWS)
                val signature = jwsObject.signature.decode()
                val actualData = JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
                val signatureVerifier = SIGNATURE_VERIFIER[jwsObject.header.algorithm.name]!!
                return signatureVerifier.verify(publicKeyObj, actualData, signature, provider)
            }

            //Currently we are getting proofValue only in ED25519Signature2020 sunbird VC
            else if (!ldProof.proofValue.isNullOrEmpty()) {
                val proofValue = ldProof.proofValue
                val signature = Multibase.decode(proofValue)
                val signatureVerifier = ED25519SignatureVerifierImpl()
                val result = signatureVerifier.verify(publicKeyObj, canonicalHashBytes, signature, provider)
                val revocationChecker: RevocationChecker = StatusListRevocationChecker()
                val isRevoked = revocationChecker.isRevoked(vcJsonLdObject)
                if (isRevoked) {
                    logger.warning("Credential is revoked.")
                    return false
                }
                logger.info("Credential is valid and not revoked.")
                return result
            }
            false
        } catch (e: Exception) {
            when (e) {
                is PublicKeyNotFoundException,
                is SignatureVerificationException -> throw e
                else -> {
                    throw UnknownException("Error while doing verification of verifiable credential")
                }
            }
        }
    }

    private fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        val confDocumentLoader = ConfigurableDocumentLoader()
        confDocumentLoader.isEnableHttps = true
        confDocumentLoader.isEnableHttp = true
        confDocumentLoader.isEnableFile = false
        return confDocumentLoader
    }
}