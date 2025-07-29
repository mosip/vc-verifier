package io.mosip.vercred.vcverifier.utils

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import foundation.identity.jsonld.ConfigurableDocumentLoader
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIALS_CONTEXT_V1_URL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIALS_CONTEXT_V2_URL
import io.mosip.vercred.vcverifier.data.DATA_MODEL
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.data.VerificationStatus
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URI
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object Util {

    fun isAndroid(): Boolean {
        return System.getProperty("java.vm.name")?.contains("Dalvik") ?: false
    }

    fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        val confDocumentLoader = ConfigurableDocumentLoader()
        confDocumentLoader.isEnableHttps = true
        confDocumentLoader.isEnableHttp = true
        confDocumentLoader.isEnableFile = false
        return confDocumentLoader
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

        return try {
            val uri = URI(value)
            (uri.scheme == "did") || (uri.scheme != null && uri.host != null)
        } catch (e: Exception) {
            false
        }
    }

    fun jsonArrayToList(jsonArray: org.json.JSONArray): List<Any> {
        return List(jsonArray.length()) { jsonArray.get(it) }
    }

    fun getContextVersion(vcJsonObject: JSONObject): DATA_MODEL? {
        if (vcJsonObject.has(CONTEXT)) {
            val contextUrl = vcJsonObject.getJSONArray(CONTEXT).get(0)
            return when (contextUrl) {
                CREDENTIALS_CONTEXT_V1_URL -> DATA_MODEL.DATA_MODEL_1_1
                CREDENTIALS_CONTEXT_V2_URL -> DATA_MODEL.DATA_MODEL_2_0
                else -> DATA_MODEL.UNSUPPORTED
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
