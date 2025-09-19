package io.mosip.vercred.vcverifier.utils

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import foundation.identity.jsonld.ConfigurableDocumentLoader
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIALS_CONTEXT_V1_URL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIALS_CONTEXT_V2_URL
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256K_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_ES256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.data.DataModel
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.data.VerificationStatus
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.ES256KSignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.PS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.RS256SignatureVerifierImpl
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URI
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object Util {

    var documentLoader : ConfigurableDocumentLoader? = null

    val SIGNATURE_VERIFIER: Map<String, SignatureVerifier> = mapOf(
        JWS_PS256_SIGN_ALGO_CONST to PS256SignatureVerifierImpl(),
        JWS_RS256_SIGN_ALGO_CONST to RS256SignatureVerifierImpl(),
        JWS_EDDSA_SIGN_ALGO_CONST to ED25519SignatureVerifierImpl(),
        JWS_ES256K_SIGN_ALGO_CONST to ES256KSignatureVerifierImpl(),
        JWS_ES256_SIGN_ALGO_CONST to ES256KSignatureVerifierImpl()
    )

    fun isAndroid(): Boolean {
        return System.getProperty("java.vm.name")?.contains("Dalvik") ?: false
    }

    fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        return documentLoader ?: run {
            val loader = ConfigurableDocumentLoader()
            loader.isEnableHttps = true
            loader.isEnableHttp = true
            loader.isEnableFile = false
            loader
        }
    }

    fun getVerificationStatus(verificationResult: VerificationResult): VerificationStatus {
        if (verificationResult.verificationStatus) {
            if (verificationResult.verificationErrorCode == CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED) {
                return VerificationStatus.EXPIRED
            }
            return VerificationStatus.SUCCESS
        }
        return VerificationStatus.INVALID
    }


    fun getId(obj: Any): String? {
        return when (obj) {
            is String -> obj
            is Map<*, *> -> obj["id"] as? String
            else -> null
        }
    }

    fun isValidUri(value: String): Boolean {

         try {
            val uri = URI(value)
             if((uri.scheme == "http" || uri.scheme == "https") && uri.host == null) {
                 return false
             }
            return (uri.scheme == "did") || (uri.scheme != null)
        } catch (e: Exception) {
            return false
        }
    }

    fun jsonArrayToList(jsonArray: JSONArray): List<Any> {
        return List(jsonArray.length()) { jsonArray[it] }
    }

    fun getContextVersion(vcJsonObject: JSONObject): DataModel? {
        if (vcJsonObject.has(CONTEXT)) {
            val contextUrl = vcJsonObject.getJSONArray(CONTEXT)[0]
            return when (contextUrl) {
                CREDENTIALS_CONTEXT_V1_URL -> DataModel.DATA_MODEL_1_1
                CREDENTIALS_CONTEXT_V2_URL -> DataModel.DATA_MODEL_2_0
                else -> DataModel.UNSUPPORTED
            }
        }
        return null
    }

    fun calculateDigest(
        algorithm: String,
        data: ByteArrayOutputStream,
    ): ByteArray =
        MessageDigest.getInstance(algorithm).digest(data.toByteArray())

    fun convertJsonToMap(jsonString: String): MutableMap<String, Any> {
        val mapper = jacksonObjectMapper()
        return mapper.readValue(
            jsonString,
            object : TypeReference<MutableMap<String, Any>>() {})
    }

    fun toX509Certificate(certificateBytes: ByteArray): X509Certificate {
        val certFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        return certFactory.generateCertificate(ByteArrayInputStream(certificateBytes)) as X509Certificate
    }

}

fun JSONArray.asIterable(): Iterable<Any?> = Iterable {
    object : Iterator<Any?> {
        private var index = 0
        override fun hasNext(): Boolean = index < this@asIterable.length()
        override fun next(): Any? = this@asIterable.get(index++)
    }
}
