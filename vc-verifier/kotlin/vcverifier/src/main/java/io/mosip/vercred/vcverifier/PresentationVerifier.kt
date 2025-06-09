package io.mosip.vercred.vcverifier

import android.os.Build
import androidx.annotation.RequiresApi
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_PROOF_TYPE_2020
import io.mosip.vercred.vcverifier.constants.Shared
import io.mosip.vercred.vcverifier.data.PresentationVerificationResult
import io.mosip.vercred.vcverifier.data.VCResult
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

    @RequiresApi(Build.VERSION_CODES.O)
    fun verify(presentation: String): PresentationVerificationResult {

        logger.info("Received Presentation For Verification - Start")
        val proofVerificationStatus: VerificationStatus
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

            if (ldProof.type == ED25519_PROOF_TYPE_2018 && !ldProof.jws.isNullOrEmpty()) {
                val signJWS: String = ldProof.jws
                val jwsObject = JWSObject.parse(signJWS)
                val signature = jwsObject.signature.decode()
                val actualData = JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
                proofVerificationStatus = if (ED25519SignatureVerifierImpl().verify(
                        publicKeyObj,
                        actualData,
                        signature,
                        provider
                    )
                ) VerificationStatus.SUCCESS else VerificationStatus.INVALID
            } else if (ldProof.type == ED25519_PROOF_TYPE_2020 && !ldProof.proofValue.isNullOrEmpty()) {
                val proofValue = ldProof.proofValue
                val signature = Multibase.decode(proofValue)
                proofVerificationStatus = if (ED25519SignatureVerifierImpl().verify(
                        publicKeyObj,
                        canonicalHashBytes,
                        signature,
                        provider
                    )
                ) VerificationStatus.SUCCESS else VerificationStatus.INVALID
            } else {
                proofVerificationStatus = VerificationStatus.INVALID
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

