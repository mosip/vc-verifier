package io.mosip.vercred.vcverifier.credentialverifier.types

import android.security.KeyStoreException
import android.util.Log
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.mosip.vercred.vcverifier.CredentialsVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifier
import io.mosip.vercred.vcverifier.exception.ProofDocumentNotFoundException
import io.mosip.vercred.vcverifier.exception.ProofTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.utils.Util
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.util.io.pem.PemReader
import java.io.IOException
import java.io.StringReader
import java.net.URI
import java.security.KeyFactory
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Objects

class LdpVcCredentialVerifier : CredentialVerifier {
    private val tag: String = CredentialsVerifier::class.java.name

    private val util: Util = Util()

    override fun verify(credential: String): Boolean {
        Log.i(tag, "Received Credentials Verification - Start")
        val confDocumentLoader: ConfigurableDocumentLoader = getConfigurableDocumentLoader()
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(credential)
        vcJsonLdObject.documentLoader = confDocumentLoader
        val ldProofWithJWS: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
        return try {
            val canonicalizer = URDNA2015Canonicalizer()
            val canonicalHashBytes: ByteArray =
                canonicalizer.canonicalize(ldProofWithJWS, vcJsonLdObject)
            val signJWS: String = ldProofWithJWS.jws
            val jwsObject: JWSObject = JWSObject.parse(signJWS)
            val vcSignBytes: ByteArray = jwsObject.signature.decode()
            val publicKeyJsonUri: URI = ldProofWithJWS.verificationMethod
            val publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri)
            if (Objects.isNull(publicKeyObj)) {
                throw PublicKeyNotFoundException("Public key object is null")
            }
            val actualData: ByteArray =
                JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
            val jwsHeader: String = jwsObject.header.algorithm.name
            verifyCredentialSignature(jwsHeader, publicKeyObj, actualData, vcSignBytes)
        } catch (e: Exception) {
            when (e) {
                is PublicKeyNotFoundException,
                is SignatureVerificationException,
                -> throw e

                else -> {
                    throw UnknownException("Error while doing verification of verifiable credential:$e")
                }
            }
        }
    }

    @Throws(CertificateException::class, KeyStoreException::class, KeyManagementException::class)
    private fun getPublicKeyFromVerificationMethod(publicKeyJsonUri: URI): PublicKey? {
        return try {
            val okHttpClient = OkHttpClient.Builder().build().newBuilder().build()
            val request = Request.Builder()
                .url(publicKeyJsonUri.toURL())
                .get()
                .build()

            val response = okHttpClient.newCall(request).execute()
            response.body?.let { responseBody ->
                val objectMapper = ObjectMapper()
                val jsonNode = objectMapper.readTree(responseBody.string())
                if (jsonNode.isObject) {
                    val responseObjectNode = jsonNode as ObjectNode
                    val publicKeyPem =
                        responseObjectNode[CredentialVerifierConstants.PUBLIC_KEY_PEM].asText()
                    val strReader = StringReader(publicKeyPem)
                    val pemReader = PemReader(strReader)
                    val pemObject = pemReader.readPemObject()
                    val pubKeyBytes = pemObject.content
                    val pubKeySpec = X509EncodedKeySpec(pubKeyBytes)
                    val keyFactory = KeyFactory.getInstance("RSA")
                    keyFactory.generatePublic(pubKeySpec)
                } else null
            }
        } catch (e: Exception) {
            Log.e(tag, "Error Generating public key object", e)
            null
        }
    }


    private fun verifyCredentialSignature(
        algorithm: String,
        publicKey: PublicKey?,
        actualData: ByteArray,
        signature: ByteArray,
    ): Boolean {
        if (algorithm == CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST) {
            try {
                Log.i(tag, "Validating signature using RS256 algorithm")
                val rsSignature: Signature =
                    Signature.getInstance(CredentialVerifierConstants.RS256_ALGORITHM)
                rsSignature.initVerify(publicKey)
                rsSignature.update(actualData)
                return rsSignature.verify(signature)
            } catch (e: Exception) {
                Log.e(tag, "Error in Verifying credentials(RS256)", e)
                throw SignatureVerificationException("Error while doing signature verification using RS256 algorithm")
            }
        }
        try {
            Log.i(tag, "Validating signature using PS256 algorithm")
            val psSignature: Signature = getPS256Signature()
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
            throw SignatureVerificationException("Error while doing signature verification using PS256 algorithm")
        }
    }

    @Throws(NoSuchAlgorithmException::class)
    private fun getPS256Signature(): Signature {
        if (util.isAndroid) {
            return Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM_ANDROID)
        }
        return Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM)
    }

    @Throws(
        CertificateException::class,
        IOException::class,
        KeyStoreException::class,
        NoSuchAlgorithmException::class,
        KeyManagementException::class
    )
    private fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        val confDocumentLoader = ConfigurableDocumentLoader()
        confDocumentLoader.isEnableHttps = true
        confDocumentLoader.isEnableHttp = true
        confDocumentLoader.isEnableFile = false
        return confDocumentLoader
    }
}