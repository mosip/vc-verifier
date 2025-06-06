package io.mosip.vercred.vcverifier

import android.os.Build
import androidx.annotation.RequiresApi
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_MESSAGE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.PresentationNotSupportedException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetterFactory
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Util
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.spec.InvalidKeySpecException
import java.util.logging.Logger


class PresentationVerifier {
    private val logger = Logger.getLogger(PresentationVerifier::class.java.name)

    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    @RequiresApi(Build.VERSION_CODES.O)
    fun verify(presentation: String): VerificationResult {

        logger.info("Received Presentation For Verification - Start")
        val status: Boolean
        try {
            if (!Util.isJsonLd(presentation)) throw PresentationNotSupportedException("Unsupported VP Token type")
            val confDocumentLoader: ConfigurableDocumentLoader =
                Util.getConfigurableDocumentLoader()
            val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(presentation)
            vcJsonLdObject.documentLoader = confDocumentLoader
            val ldProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

            val canonicalHashBytes = URDNA2015Canonicalizer().canonicalize(ldProof, vcJsonLdObject)

            val verificationMethod = ldProof.verificationMethod
            val publicKeyObj = PublicKeyGetterFactory().get(verificationMethod)

            if (ldProof.type == ED25519_KEY_TYPE_2018 && !ldProof.jws.isNullOrEmpty()) {
                val signJWS: String = ldProof.jws
                val jwsObject = JWSObject.parse(signJWS)
                val signature = jwsObject.signature.decode()
                val actualData = JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
                status = ED25519SignatureVerifierImpl().verify(
                    publicKeyObj,
                    actualData,
                    signature,
                    provider
                )
            } else if (ldProof.type == ED25519_KEY_TYPE_2020 && !ldProof.proofValue.isNullOrEmpty()) {
                val proofValue = ldProof.proofValue
                val signature = Multibase.decode(proofValue)
                status = ED25519SignatureVerifierImpl().verify(
                    publicKeyObj,
                    canonicalHashBytes,
                    signature,
                    provider
                )
            } else {
                status = false
            }

        } catch (e: Exception) {
            when (e) {
                is PublicKeyNotFoundException,
                is IllegalStateException,
                is InvalidKeySpecException,
                is SignatureNotSupportedException,
                is SignatureVerificationException,
                is PresentationNotSupportedException -> throw e

                else -> {
                    throw UnknownException("Error while doing verification of verifiable presentation")
                }
            }
        }
        if (!status) {
            return VerificationResult(
                false,
                ERROR_MESSAGE_VERIFICATION_FAILED,
                ERROR_CODE_VERIFICATION_FAILED
            )
        }
        return VerificationResult(true, "", "")
    }
}

