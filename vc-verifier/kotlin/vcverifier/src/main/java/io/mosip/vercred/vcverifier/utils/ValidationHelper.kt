package io.mosip.vercred.vcverifier.utils

import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ALGORITHMS_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ALGORITHM_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_FIELD
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_PROOF_TYPE_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.JWS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF_TYPES_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.data.DATA_MODEL
import io.mosip.vercred.vcverifier.data.VerificationResult
import org.json.JSONArray
import org.json.JSONObject

class ValidationHelper {

     fun validateCredentialStatus(credentialStatus: Any, dateModel: DATA_MODEL): VerificationResult {

        when (credentialStatus) {
            is JSONArray -> {
                for (i in 0 until credentialStatus.length()) {
                    val statusObject = credentialStatus.getJSONObject(i)
                    val result = validateSingleCredentialStatus(statusObject, dateModel)
                    if (!result.verificationStatus) return result
                }
            }
            is JSONObject -> {
                val result = validateSingleCredentialStatus(credentialStatus, dateModel)
                if (!result.verificationStatus) return result
            }
            else -> return VerificationResult(false, "$ERROR_INVALID_FIELD$CREDENTIAL_STATUS")
        }

        return VerificationResult(true)
    }

    private fun validateSingleCredentialStatus(statusObject: JSONObject, dateModel: DATA_MODEL): VerificationResult {
        if (!statusObject.has(TYPE)) {
            return VerificationResult(false, "$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE")
        }

        if (dateModel == DATA_MODEL.DATA_MODEL_1_1 && !statusObject.has(ID)) {
            return VerificationResult(false, "$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$ID")
        }

        statusObject.optString(ID).takeIf { it.isNotEmpty() }?.let { id ->
            if (!Util().isValidUri(id)) {
                return VerificationResult(false, "$ERROR_INVALID_URI$CREDENTIAL_STATUS.$ID")
            }
        }

        return VerificationResult(true)
    }

    fun checkMandatoryFields(vcJsonObject: JSONObject, fields: List<String>): VerificationResult {

        for (field in fields) {
            val keys = field.split(".")
            var currentJson: JSONObject? = vcJsonObject

            for (key in keys) {
                if (currentJson != null && currentJson.has(key)) {
                    if (currentJson.get(key) is JSONObject) {
                        currentJson = currentJson.getJSONObject(key)
                    } else {
                        break
                    }
                } else {
                    return VerificationResult(false, "$ERROR_MISSING_REQUIRED_FIELDS$field")
                }
            }
        }

        return VerificationResult(true)
    }

    fun validateProof(vcJsonString: String): VerificationResult {
        val vcJsonObject = JSONObject(vcJsonString)

        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(vcJsonString)
        val ldProof : LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

        if(vcJsonObject.getJSONObject(PROOF).has(JWS)){
            val jwsToken: String = ldProof.jws
            val algorithmName: String = JWSObject.parse(jwsToken).header.algorithm.name
            if(jwsToken.isNullOrEmpty() || !ALGORITHMS_SUPPORTED.contains(algorithmName)){
                return VerificationResult(false, ERROR_ALGORITHM_NOT_SUPPORTED )
            }
        }

        val ldProofType: String = ldProof.type
        if (!PROOF_TYPES_SUPPORTED.contains(ldProofType)) {
            return VerificationResult(false, ERROR_PROOF_TYPE_NOT_SUPPORTED)
        }

        return VerificationResult(true)
    }
}