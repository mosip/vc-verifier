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
import io.ipfs.multibase.Base58
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_SIGNATURE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_SIGNATURE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_SIGNATURE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.VERIFICATION_METHOD
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.PS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.RS256SignatureVerifierImpl
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemReader
import java.io.StringReader
import java.net.URI
import java.security.KeyFactory
import java.security.KeyManagementException
import java.security.PublicKey
import java.security.Security
import java.security.cert.CertificateException
import java.security.spec.X509EncodedKeySpec

class LdpVerifier {

    private val tag: String = LdpVerifier::class.java.name
    private var provider: BouncyCastleProvider = BouncyCastleProvider()
    private val SIGNATURE_VERIFIER: Map<String, SignatureVerifier> = mapOf(
        JWS_PS256_SIGN_ALGO_CONST to PS256SignatureVerifierImpl(),
        JWS_RS256_SIGN_ALGO_CONST to RS256SignatureVerifierImpl(),
        JWS_EDDSA_SIGN_ALGO_CONST to ED25519SignatureVerifierImpl()
    )
    private val PUBLIC_KEY_ALGORITHM: Map<String, String> = mapOf(
        RSA_SIGNATURE to RSA_ALGORITHM,
        ED25519_SIGNATURE_2018 to ED25519_ALGORITHM,
        ED25519_SIGNATURE_2020 to ED25519_ALGORITHM
    )
    private val RESOLVER_API = "https://resolver.identity.foundation/1.0/identifiers/"

    init {
        Security.addProvider(provider);
    }

    fun verify(credential: String): Boolean {

        Log.i(tag, "Received Credentials Verification - Start")
        val confDocumentLoader: ConfigurableDocumentLoader = getConfigurableDocumentLoader()
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(credential)
        vcJsonLdObject.documentLoader = confDocumentLoader

        return try {
            val ldProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
            val canonicalizer = URDNA2015Canonicalizer()
            val canonicalHashBytes: ByteArray = canonicalizer.canonicalize(ldProof, vcJsonLdObject)

            if(!ldProof.jws.isNullOrEmpty()) {
                val signJWS: String = ldProof.jws
                val jwsObject: JWSObject = JWSObject.parse(signJWS)
                val signature: ByteArray = jwsObject.signature.decode()
                val actualData: ByteArray = JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
                val publicKeyObj = getPublicKeyFromHttpVerificationMethod(ldProof.verificationMethod, ldProof.type)
                val signatureVerifier: SignatureVerifier = SIGNATURE_VERIFIER[jwsObject.header.algorithm.name]!!
                return signatureVerifier.verify(publicKeyObj!!, actualData, signature, provider)
            }

            else if(!ldProof.proofValue.isNullOrEmpty()){
                val proofValue: String = ldProof.proofValue
                val signature = Base58.decode(proofValue.substring(1))
                val publicKeyObj = getPublicKeyFromDidVerificationMethod(ldProof.verificationMethod, ldProof.type)
                val signatureVerifier: SignatureVerifier = ED25519SignatureVerifierImpl()
                return signatureVerifier.verify(publicKeyObj!!, canonicalHashBytes, signature, provider)
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

    @Throws(CertificateException::class, KeyStoreException::class, KeyManagementException::class)
    private fun getPublicKeyFromHttpVerificationMethod(verificationMethod: URI, signatureSuite: String ): PublicKey? {
        return try {
            val okHttpClient = OkHttpClient.Builder().build().newBuilder().build()
            val request = Request.Builder()
                .url(verificationMethod.toURL())
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
                    val keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM[signatureSuite], provider)
                    keyFactory.generatePublic(pubKeySpec)
                } else
                    throw PublicKeyNotFoundException("Public key object is null")
            }
        } catch (e: Exception) {
            Log.e(tag, "Error Generating public key object", e)
            throw PublicKeyNotFoundException("Public key object is null")
        }
    }

    private fun getPublicKeyFromDidVerificationMethod(verificationMethod: URI, signatureSuite: String): PublicKey? {
        val resolverUrl = "$RESOLVER_API$verificationMethod"
        try {
            val request = Request.Builder()
                .url(URI(resolverUrl).toURL())
                .get()
                .build()
            val response = OkHttpClient.Builder().build().newCall(request).execute()
            response.body?.use { responseBody ->
                val jsonNode = ObjectMapper().readTree(responseBody.string())
                if (jsonNode.isObject) {
                    val publicKeyMultibase = getPublicKeyMultiBase(jsonNode as ObjectNode)
                    val rawPublicKeyWithHeader = Base58.decode(publicKeyMultibase.substring(1))
                    if (isEd25519PublicKey(rawPublicKeyWithHeader)) {
                        val rawPublicKey = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
                        val publicKey = Hex.decode(DER_PUBLIC_KEY_PREFIX) + rawPublicKey
                        val pubKeySpec = X509EncodedKeySpec(publicKey)
                        val keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM[signatureSuite], provider)
                        return keyFactory.generatePublic(pubKeySpec)
                    }
                }
            }
            throw PublicKeyNotFoundException("Public key object is null")
        } catch (e: Exception) {
            Log.e(tag, "Error generating public key object", e)
            throw PublicKeyNotFoundException("Public key object is null")
        }
    }

    private fun getPublicKeyMultiBase(responseObjectNode: ObjectNode): String =
        responseObjectNode.get("didDocument")
            .get(VERIFICATION_METHOD)[0].get(PUBLIC_KEY_MULTIBASE).asText()

    //Ref: https://w3c.github.io/vc-di-eddsa/#multikey
    private fun isEd25519PublicKey(rawPublicKeyWithHeader: ByteArray) =
        rawPublicKeyWithHeader.size > 2 &&
                rawPublicKeyWithHeader[0] == 0xed.toByte() &&
                rawPublicKeyWithHeader[1] == 0x01.toByte()


    private fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        val confDocumentLoader = ConfigurableDocumentLoader()
        confDocumentLoader.isEnableHttps = true
        confDocumentLoader.isEnableHttp = true
        confDocumentLoader.isEnableFile = false
        return confDocumentLoader
    }
}