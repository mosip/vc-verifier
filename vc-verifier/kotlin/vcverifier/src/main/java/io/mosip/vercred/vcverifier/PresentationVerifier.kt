package io.mosip.vercred.vcverifier

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JSON_WEB_KEY_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.Shared
import io.mosip.vercred.vcverifier.data.PresentationVerificationResult
import io.mosip.vercred.vcverifier.data.VCResult
import io.mosip.vercred.vcverifier.data.VPVerificationStatus
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.data.VerificationStatus
import io.mosip.vercred.vcverifier.exception.PresentationNotSupportedException
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetterFactory
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.asIterable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.JSONArray
import org.json.JSONObject
import java.security.spec.InvalidKeySpecException
import java.util.logging.Logger


class PresentationVerifier {
    private val logger = Logger.getLogger(PresentationVerifier::class.java.name)

    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    private val credentialsVerifier: CredentialsVerifier = CredentialsVerifier()

    fun verify(presentation: String): PresentationVerificationResult {

        logger.info("Received Presentation For Verification - Start")
        val proofVerificationStatus: VPVerificationStatus
        val vcJsonLdObject: JsonLDObject

        try {
            vcJsonLdObject = JsonLDObject.fromJson(presentation)
        } catch (e: RuntimeException) {
            throw PresentationNotSupportedException("Unsupported VP Token type")
        }

        try {
            vcJsonLdObject.documentLoader = Util.getConfigurableDocumentLoader()
            val ldProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

            val canonicalHashBytes = URDNA2015Canonicalizer().canonicalize(ldProof, vcJsonLdObject)

            val verificationMethod = ldProof.verificationMethod
            val publicKeyObj = PublicKeyGetterFactory().get(verificationMethod)

            when {
                ldProof.type == ED25519_PROOF_TYPE_2018 && !ldProof.jws.isNullOrEmpty() -> {
                    val signJWS: String = ldProof.jws
                    val jwsObject = JWSObject.parse(signJWS)
                    val signature = jwsObject.signature.decode()
                    val actualData =
                        JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
                    proofVerificationStatus = if (ED25519SignatureVerifierImpl().verify(
                            publicKeyObj,
                            actualData,
                            signature,
                            provider
                        )
                    ) VPVerificationStatus.VALID else VPVerificationStatus.INVALID
                }

                ldProof.type == ED25519_PROOF_TYPE_2020 && !ldProof.proofValue.isNullOrEmpty() -> {
                    val proofValue = ldProof.proofValue
                    val signature = Multibase.decode(proofValue)
                    proofVerificationStatus = if (ED25519SignatureVerifierImpl().verify(
                            publicKeyObj,
                            canonicalHashBytes,
                            signature,
                            provider
                        )
                    ) VPVerificationStatus.VALID else VPVerificationStatus.INVALID
                }

                ldProof.type == JSON_WEB_KEY_PROOF_TYPE_2020 && !ldProof.jws.isNullOrEmpty() -> {
                    val signJWS: String = ldProof.jws
                    val jwsObject = JWSObject.parse(signJWS)
                    if (jwsObject.header.algorithm != JWSAlgorithm.EdDSA) throw SignatureNotSupportedException(
                        "Unsupported jws signature algorithm"
                    )
                    val signature = jwsObject.signature.decode()
                    val actualData =
                        JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)

                    proofVerificationStatus = if (ED25519SignatureVerifierImpl().verify(
                            publicKeyObj,
                            actualData,
                            signature,
                            provider
                        )
                    ) VPVerificationStatus.VALID else VPVerificationStatus.INVALID
                }

                else -> {
                    proofVerificationStatus = VPVerificationStatus.INVALID
                }
            }

        } catch (e: Exception) {
            when (e) {
                is PublicKeyNotFoundException,
                is IllegalStateException,
                is InvalidKeySpecException,
                is SignatureNotSupportedException,
                is SignatureVerificationException -> throw e

                else -> {
                    throw UnknownException("Error while doing verification of verifiable presentation")
                }
            }
        }

        val vcVerificationResults: List<VCResult> =
            getVCVerificationResults(JSONObject(presentation).getJSONArray(Shared.KEY_VERIFIABLE_CREDENTIAL))

        return PresentationVerificationResult(proofVerificationStatus, vcVerificationResults)
    }

    private fun getVCVerificationResults(verifiableCredentials: JSONArray): List<VCResult> {
        val verificationResults: MutableList<VCResult> = ArrayList()
        verifiableCredentials.asIterable().forEachIndexed { index, item ->
            val verificationResult: VerificationResult =
                credentialsVerifier.verify((item as JSONObject).toString(), CredentialFormat.LDP_VC)
            val singleVCVerification: VerificationStatus =
                Util.getVerificationStatus(verificationResult)
            /*
            Here we are adding the entire VC as a string in the method response. We know that this is not very efficient.
            But in newer draft of OpenId4VP specifications the Presentation Exchange
            is fully removed so we rather not use the submission_requirements for giving the VC reference
            for response. As of now we could not find anything unique that can be referred in a vp_token
            VC we will be going with the approach of sending whole VC back in response.
            */
            verificationResults.add(
                VCResult(
                    item.toString(),
                    singleVCVerification
                )
            )
        }
        return verificationResults
    }

}

