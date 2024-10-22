package io.mosip.vercred.vcverifier.credentialverifier.verifier

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
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_ALGORITHM
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.PS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.RS256SignatureVerifierImpl
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemReader
import java.io.StringReader
import java.net.URI
import java.security.KeyFactory
import java.security.KeyManagementException
import java.security.PublicKey
import java.security.Security
import java.security.cert.CertificateException
import java.security.spec.X509EncodedKeySpec
import java.util.Objects

class LdpVerifier {

    private val tag: String = LdpVerifier::class.java.name
    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    private val SIGNATURE_VERIFIER: Map<String, SignatureVerifier> = mapOf(
        CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST to PS256SignatureVerifierImpl(),
        CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST to RS256SignatureVerifierImpl(),
        CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST to ED25519SignatureVerifierImpl()
    )

    private val PUBLIC_KEY_ALGORITHM: Map<String, String> = mapOf(
        CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST to RSA_ALGORITHM,
        CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST to RSA_ALGORITHM,
        CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST to ED25519_ALGORITHM
    )

    init {
        Security.addProvider(provider);
    }

     fun verify(credential: String): Boolean {

        Log.i(tag, "Received Credentials Verification - Start")
        val confDocumentLoader: ConfigurableDocumentLoader = getConfigurableDocumentLoader()
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(credential)
        vcJsonLdObject.documentLoader = confDocumentLoader
        val ldProofWithJWS: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
        return try {
            val canonicalizer = URDNA2015Canonicalizer()
            val canonicalHashBytes: ByteArray = canonicalizer.canonicalize(ldProofWithJWS, vcJsonLdObject)
            val signJWS: String = ldProofWithJWS.jws
            val jwsObject: JWSObject = JWSObject.parse(signJWS)
            val vcSignBytes: ByteArray = jwsObject.signature.decode()
            val publicKeyJsonUri: URI = ldProofWithJWS.verificationMethod
            val actualData: ByteArray = JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
            val jwsHeader: String = jwsObject.header.algorithm.name
            val publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri, PUBLIC_KEY_ALGORITHM[jwsHeader]!!)
            if (Objects.isNull(publicKeyObj)) {
                throw PublicKeyNotFoundException("Public key object is null")
            }
            val signatureVerifier: SignatureVerifier = SIGNATURE_VERIFIER[jwsHeader]!!
            signatureVerifier.verify(publicKeyObj!!, actualData, vcSignBytes, provider)
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

    @Throws(CertificateException::class, KeyStoreException::class, KeyManagementException::class)
    private fun getPublicKeyFromVerificationMethod(publicKeyJsonUri: URI, algo: String ): PublicKey? {
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
                    val keyFactory = KeyFactory.getInstance(algo, provider)
                    keyFactory.generatePublic(pubKeySpec)
                } else null
            }
        } catch (e: Exception) {
            Log.e(tag, "Error Generating public key object", e)
            null
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