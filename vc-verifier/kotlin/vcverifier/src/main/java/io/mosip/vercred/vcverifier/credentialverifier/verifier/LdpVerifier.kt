package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.keyResolver.PublicKeyGetterFactory
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.Util.SIGNATURE_VERIFIER
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.util.logging.Logger


class LdpVerifier {

    private val logger = Logger.getLogger(LdpVerifier::class.java.name)
    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    init {
        Security.addProvider(provider)
    }

    fun verify(credential: String): Boolean {

        logger.info("Received Credentials Verification - Start")
        val confDocumentLoader: ConfigurableDocumentLoader = Util.getConfigurableDocumentLoader()
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
                val signatureVerifier = SIGNATURE_VERIFIER[jwsObject.header.algorithm.name]
                    ?: throw SignatureNotSupportedException("Unsupported jws signature algorithm")
                return signatureVerifier.verify(publicKeyObj, actualData, signature)
            }

            //Currently we are getting proofValue only in ED25519Signature2020 sunbird VC
            else if (!ldProof.proofValue.isNullOrEmpty()) {
                val proofValue = ldProof.proofValue
                val signature = Multibase.decode(proofValue)
                val signatureVerifier = ED25519SignatureVerifierImpl()
                return signatureVerifier.verify(publicKeyObj, canonicalHashBytes, signature)
            }
            false
        } catch (exception: Exception) {
            when (exception) {
                is PublicKeyNotFoundException,
                is UnsupportedDidUrl,
                is SignatureVerificationException -> throw exception

                else -> {
                    throw UnknownException("Error while doing verification of verifiable credential: $exception")
                }
            }
        }
    }
}