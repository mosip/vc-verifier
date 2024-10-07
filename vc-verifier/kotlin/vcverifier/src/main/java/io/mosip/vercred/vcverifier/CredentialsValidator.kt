package io.mosip.vercred.vcverifier

import org.json.JSONObject

class CredentialsValidator {
    private val tag: String = CredentialsValidator::class.java.name

    private val requiredFields = listOf(
        "credential.id",
        "credential.issuanceDate",
        "credential.issuer",
        "credential.proof",
        "credential.type",
        "credential.@context",
        "credential"
    )

    fun validateCredential(vcJsonString: String?): VerificationResult{
        val vcJsonObject = JSONObject(vcJsonString)
        return validateFields(vcJsonObject, requiredFields)
    }

    private fun validateFields(json: JSONObject, fields: List<String>): VerificationResult {
        for (field in fields) {
            val keys = field.split(".")
            var currentJson: JSONObject? = json

            for (key in keys) {
                if (currentJson != null && currentJson.has(key)) {
                    if (currentJson.get(key) is JSONObject) {
                        currentJson = currentJson.getJSONObject(key)
                    } else {
                        break
                    }
                } else {
                    return VerificationResult(false, "Missing required field: $field")
                }
            }
        }
        return VerificationResult(true)
    }

}

data class VerificationResult(
    val verificationStatus: Boolean,
    val verificationErrorMessage: String = ""
)

