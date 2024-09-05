package io.mosip.vercred.vcverifier

import android.util.Log
import com.apicatalog.jsonld.JsonLdError
import com.apicatalog.jsonld.document.JsonDocument
import com.fasterxml.jackson.databind.node.ObjectNode
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.ProofDocumentNotFoundException
import io.mosip.vercred.vcverifier.exception.ProofTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.PubicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.UnknownException
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.springframework.http.HttpMethod
import org.springframework.web.client.RestTemplate
import java.io.IOException
import java.io.StringReader
import java.net.URI
import java.net.URISyntaxException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.spec.InvalidKeySpecException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Objects


class CredentialsVerifier {
    private val tag: String = CredentialsVerifier::class.java.name

    private val vcContextUrlMap: Map<String, String>? = null
    private val configServerFileStorageUrl: String? = null

    fun verifyCredentials(credentials: String?): Boolean {
        Log.i(tag,"Received Credentials Verification - Start.")
        val confDocumentLoader: ConfigurableDocumentLoader = configurableDocumentLoader
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(credentials)
        vcJsonLdObject.documentLoader = confDocumentLoader
        val ldProofWithJWS: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
        if (Objects.isNull(ldProofWithJWS)) {
            Log.e(tag,"Proof document is not available in the received credentials.")
            throw ProofDocumentNotFoundException("Proof document is not available in the received credentials.")
        }
        val ldProofTerm: String = ldProofWithJWS.type
        if (CredentialVerifierConstants.SIGNATURE_SUITE_TERM != ldProofTerm) {
            Log.e(tag, "Proof Type available in received credentials is not matching with supported proof terms. Received Type: $ldProofTerm")
            throw ProofTypeNotSupportedException("Proof Type available in received credentials is not matching with supported proof terms.")
        }
        return try {
            val canonicalizer = URDNA2015Canonicalizer()
            val canonicalHashBytes: ByteArray = canonicalizer.canonicalize(ldProofWithJWS, vcJsonLdObject)
            Log.i(tag,"Completed Canonicalization for the received credentials.")
            val signJWS: String = ldProofWithJWS.jws
            val jwsObject: JWSObject = JWSObject.parse(signJWS)
            val vcSignBytes: ByteArray = jwsObject.signature.decode()
            val publicKeyJsonUri: URI = ldProofWithJWS.verificationMethod
            val publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri)
            if (Objects.isNull(publicKeyObj)) {
                Log.e(tag,"Public key object is null, returning false.")
                throw PubicKeyNotFoundException("Public key object is null.")
            }
            Log.i(tag,"Completed downloading public key from the issuer domain and constructed public key object.")
            val actualData: ByteArray = JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
            val jwsHeader: String = jwsObject.header.algorithm.name
            Log.i(tag,"Performing signature verification after downloading the public key.")
            verifyCredentialSignature(jwsHeader, publicKeyObj, actualData, vcSignBytes)
        } catch (e: Exception) {
            Log.e(tag, "Error in doing verifiable credential verification process.", e)
            throw UnknownException("Error in doing verifiable credential verification process.")
        }
    }

    private fun getPublicKeyFromVerificationMethod(publicKeyJsonUri: URI): PublicKey? {
        try {
            val restTemplate = RestTemplate()
            val response: ObjectNode? =
                restTemplate.exchange(publicKeyJsonUri, HttpMethod.GET, null, ObjectNode::class.java).body
            val publicKeyPem: String? = response?.get(CredentialVerifierConstants.PUBLIC_KEY_PEM)?.asText()
            Log.i(tag,"public key download completed.")
            val strReader = StringReader(publicKeyPem)
            val pemReader = PemReader(strReader)
            val pemObject: PemObject = pemReader.readPemObject()
            val pubKeyBytes: ByteArray = pemObject.content
            val pubKeySpec = X509EncodedKeySpec(pubKeyBytes)
            val keyFactory = KeyFactory.getInstance("RSA")
            return keyFactory.generatePublic(pubKeySpec)
        } catch (e: IOException) {
            Log.e(tag,"Error Generating public key object.", e)
        } catch (e: NoSuchAlgorithmException) {
            Log.e(tag,"Error Generating public key object.", e)
        } catch (e: InvalidKeySpecException) {
            Log.e(tag,"Error Generating public key object.", e)
        }
        return null
    }

    private fun verifyCredentialSignature(
        algorithm: String,
        publicKey: PublicKey?,
        actualData: ByteArray,
        signature: ByteArray
    ): Boolean {
        if (algorithm == CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST) {
            try {
                Log.i(tag,"Validating signature using RS256 algorithm.")
                val rsSignature: Signature = Signature.getInstance(CredentialVerifierConstants.RS256_ALGORITHM)
                rsSignature.initVerify(publicKey)
                rsSignature.update(actualData)
                return rsSignature.verify(signature)
            } catch (e: NoSuchAlgorithmException) {
                Log.e(tag,"Error in Verifying credentials(RS256).", e)
            } catch (e: InvalidKeyException) {
                Log.e(tag,"Error in Verifying credentials(RS256).", e)
            } catch (e: SignatureException) {
                Log.e(tag,"Error in Verifying credentials(RS256).", e)
            }
        }
        try {
            Log.i(tag,"Validating signature using PS256 algorithm.")
            val psSignature: Signature = Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM)
            val pssParamSpec = PSSParameterSpec(
                CredentialVerifierConstants.PSS_PARAM_SHA_256,
                CredentialVerifierConstants.PSS_PARAM_MGF1,
                MGF1ParameterSpec.SHA256,
                CredentialVerifierConstants.PSS_PARAM_SALT_LEN,
                CredentialVerifierConstants.PSS_PARAM_TF
            )
            psSignature.setParameter(pssParamSpec)
            psSignature.initVerify(publicKey)
            psSignature.update(actualData)
            return psSignature.verify(signature)
        } catch (e: NoSuchAlgorithmException) {
            Log.e(tag,"Error in Verifying credentials(PS256).", e)
        } catch (e: InvalidKeyException) {
            Log.e(tag,"Error in Verifying credentials(PS256).", e)
        } catch (e: SignatureException) {
            Log.e(tag,"Error in Verifying credentials(PS256).", e)
        } catch (e: InvalidAlgorithmParameterException) {
            Log.e(tag,"Error in Verifying credentials(PS256).", e)
        }
        return false
    }

    private val configurableDocumentLoader: ConfigurableDocumentLoader
        get() {
            Log.i(tag,"Creating ConfigurableDocumentLoader Object with configured URLs.")
            val restTemplate = RestTemplate()
            val confDocumentLoader: ConfigurableDocumentLoader
            if (Objects.isNull(vcContextUrlMap)) {
                Log.w(tag,
                    "CredentialsVerifier::getConfigurableDocumentLoader " +
                            "Warning - Verifiable Credential Context URL Map not configured."
                )
                confDocumentLoader = ConfigurableDocumentLoader()
                confDocumentLoader.isEnableHttps = true
                confDocumentLoader.isEnableHttp = true
                confDocumentLoader.isEnableFile = false
            } else {
                val jsonDocumentCacheMap: MutableMap<URI, JsonDocument> = HashMap()
                vcContextUrlMap!!.keys.stream().forEach { contextUrl: String ->
                    val localConfigUri = vcContextUrlMap[contextUrl]
                    val vcContextJson: String? = restTemplate.getForObject(
                        configServerFileStorageUrl + localConfigUri,
                        String::class.java
                    )
                    try {
                        val jsonDocument: JsonDocument = JsonDocument.of(StringReader(vcContextJson))
                        jsonDocumentCacheMap[URI(contextUrl)] = jsonDocument
                    } catch (e: URISyntaxException) {
                        Log.e(tag,
                            "Error downloading Context files from config service.localConfigUri: " + localConfigUri +
                                    "contextUrl: " + contextUrl, e
                        )
                    } catch (e: JsonLdError) {
                        Log.e(tag,
                            "Error downloading Context files from config service.localConfigUri: " + localConfigUri +
                                    "contextUrl: " + contextUrl, e
                        )
                    }
                }
                confDocumentLoader = ConfigurableDocumentLoader(jsonDocumentCacheMap)
                confDocumentLoader.isEnableHttps = false
                confDocumentLoader.isEnableHttp = false
                confDocumentLoader.isEnableFile = false
                Log.i(tag,
                    "CredentialsVerifier::getConfigurableDocumentLoader" +
                            "Added cache for the list of configured URL Map: " + jsonDocumentCacheMap.keys.toString()
                )
            }
            return confDocumentLoader
        }
}