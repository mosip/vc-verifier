package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Base58
import io.ipfs.multibase.Multibase
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
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
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
import java.security.PublicKey
import java.security.Security
import java.security.spec.X509EncodedKeySpec
import java.util.logging.Logger


class LdpVerifier {

    private val logger = Logger.getLogger(LdpVerifier::class.java.name)

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

        logger.info("Received Credentials Verification - Start")
        val confDocumentLoader: ConfigurableDocumentLoader = getConfigurableDocumentLoader()
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(credential)
        vcJsonLdObject.documentLoader = confDocumentLoader

        return try {
            val ldProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
            val canonicalizer = URDNA2015Canonicalizer()
            val canonicalHashBytes = canonicalizer.canonicalize(ldProof, vcJsonLdObject)
            val verificationMethod = ldProof.verificationMethod
            val publicKeyObj = getPublicKeyObject(verificationMethod, ldProof)

            //TODO: make algorithm factory

            if (!ldProof.jws.isNullOrEmpty()) {
                val signJWS: String = ldProof.jws
                val jwsObject = JWSObject.parse(signJWS)
                val signature = jwsObject.signature.decode()
                val actualData = JWSUtil.getJwsSigningInput(jwsObject.header, canonicalHashBytes)
                val signatureVerifier = SIGNATURE_VERIFIER[jwsObject.header.algorithm.name]!!
                return signatureVerifier.verify(publicKeyObj!!, actualData, signature, provider)
            } else if (!ldProof.proofValue.isNullOrEmpty()) {
                val proofValue = ldProof.proofValue
                val signature = Multibase.decode(proofValue)
                val signatureVerifier = ED25519SignatureVerifierImpl()
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

    private fun getPublicKeyObject(verificationMethod: URI, ldProof: LdProof): PublicKey? {
        val verificationMethodStr = verificationMethod.toString()
        val publicKeyStr = when {
            verificationMethodStr.startsWith("did:web") -> getPublicKeyStrFromDidVerificationMethod(verificationMethod)
            verificationMethodStr.startsWith("http") -> getPublicKeyStrFromHttpVerificationMethod(verificationMethod)
            else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
        }
        return when {
            isPemPublicKey(publicKeyStr!!) -> getPublicKeyObjectFromPemPublicKey(publicKeyStr, ldProof.type)
            isPublicKeyMultibase(publicKeyStr) -> getPublicKeyObjectFromPublicKeyMultibase(publicKeyStr, ldProof.type)
            else -> throw PublicKeyTypeNotSupportedException("Public Key type is not supported")
        }
    }


    private fun getPublicKeyStrFromHttpVerificationMethod(verificationMethod: URI): String? {
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
                    responseObjectNode[CredentialVerifierConstants.PUBLIC_KEY_PEM].asText()
                } else
                    throw PublicKeyNotFoundException("Public key string not found")
            }
        } catch (e: Exception) {
            logger.severe("Error fetching public key string $e")
            throw PublicKeyNotFoundException("Public key string not found")
        }
    }

    private fun getPublicKeyObjectFromPemPublicKey(publicKeyPem: String, signatureSuite: String): PublicKey? {
        try {
            val strReader = StringReader(publicKeyPem)
            val pemReader = PemReader(strReader)
            val pemObject = pemReader.readPemObject()
            val pubKeyBytes = pemObject.content
            val pubKeySpec = X509EncodedKeySpec(pubKeyBytes)
            val keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM[signatureSuite], provider)
            return keyFactory.generatePublic(pubKeySpec)
        } catch (e: Exception) {
            logger.severe("Error Generating public key object$e")
            throw PublicKeyNotFoundException("Public key object is null")
        }
    }

    private fun getPublicKeyObjectFromPublicKeyMultibase(publicKeyPem: String, signatureSuite: String): PublicKey? {
        try {
            val rawPublicKeyWithHeader = Base58.decode(publicKeyPem.substring(1))
            val rawPublicKey = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
            val publicKey = Hex.decode(DER_PUBLIC_KEY_PREFIX) + rawPublicKey

            val pubKeySpec = X509EncodedKeySpec(publicKey)
            val keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM[signatureSuite], provider)
            return keyFactory.generatePublic(pubKeySpec)
        } catch (e: Exception) {
            logger.severe("Error Generating public key object$e")
            throw PublicKeyNotFoundException("Public key object is null")
        }
    }

    private fun getPublicKeyStrFromDidVerificationMethod(verificationMethod: URI, ): String {
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

                    return publicKeyMultibase

                }
            }
            throw PublicKeyNotFoundException("Public key string not found")
        } catch (e: Exception) {
            logger.severe("Error fetching public key string $e")
            throw PublicKeyNotFoundException("Public key string not found")
        }
    }

    private fun getPublicKeyMultiBase(responseObjectNode: ObjectNode): String =
        responseObjectNode.get("didDocument")
            .get(VERIFICATION_METHOD)[0].get(PUBLIC_KEY_MULTIBASE).asText()

    private fun isPublicKeyMultibase(publicKeyMultibase: String): Boolean {
        val rawPublicKeyWithHeader = Base58.decode(publicKeyMultibase.substring(1))
        return rawPublicKeyWithHeader.size > 2 &&
                rawPublicKeyWithHeader[0] == 0xed.toByte() &&
                rawPublicKeyWithHeader[1] == 0x01.toByte()
    }

    private fun isPemPublicKey(str: String) = str.contains("BEGIN PUBLIC KEY")

    private fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        val confDocumentLoader = ConfigurableDocumentLoader()
        confDocumentLoader.isEnableHttps = true
        confDocumentLoader.isEnableHttp = true
        confDocumentLoader.isEnableFile = false
        return confDocumentLoader
    }
}