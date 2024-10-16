package io.mosip.vercred.vcverifier.utils

import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ALGORITHMS_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ALGORITHM_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_FIELD
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_PROOF_TYPE_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.JWS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.LANGUAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF_TYPES_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.data.VerificationResult
import org.json.JSONArray
import org.json.JSONObject

class ValidationHelper {


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
    fun validateCredentialSubject(vcJsonObject: JSONObject): VerificationResult {
        val credentialSubject = vcJsonObject.get(CREDENTIAL_SUBJECT)
        return validateJsonObjectOrArray(credentialSubject, ::validateSingleCredentialObject, "$ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT")
    }

    fun validateFieldsByIdAndType(vcJsonObject: JSONObject, fieldName: String, idMandatoryFields: List<String>): VerificationResult {
        val fieldValue = vcJsonObject.get(fieldName)
        return validateJsonObjectOrArray(fieldValue, { obj -> validateSingleObject(fieldName, obj, idMandatoryFields) }, "$ERROR_INVALID_FIELD$fieldName")
    }

    private fun validateJsonObjectOrArray(
        value: Any,
        validator: (JSONObject) -> VerificationResult,
        errorMessage: String
    ): VerificationResult {
        return when (value) {
            is JSONArray -> {
                for (i in 0 until value.length()) {
                    val jsonObject = value.getJSONObject(i)
                    val result = validator(jsonObject)
                    if (!result.verificationStatus) return result
                }
                VerificationResult(true)
            }
            is JSONObject -> validator(value)
            else -> VerificationResult(false, errorMessage)
        }
    }

    private fun validateSingleCredentialObject(credentialSubjectObject: JSONObject): VerificationResult {
        if (credentialSubjectObject.has(ID) && !Util().isValidUri(credentialSubjectObject.optString(ID))) {
            return  VerificationResult(false, "$ERROR_INVALID_URI$CREDENTIAL_SUBJECT.$ID")
        }
        return VerificationResult(true)
    }

    private fun validateSingleObject(fieldName: String, fieldValueObject: JSONObject, idMandatoryFields: List<String>): VerificationResult {
        if (!fieldValueObject.has(TYPE)) {
            return VerificationResult(false, "$ERROR_MISSING_REQUIRED_FIELDS$fieldName.$TYPE")
        }

        val isIDMandatoryField = idMandatoryFields.contains(fieldName)
        if (isIDMandatoryField && !fieldValueObject.has(ID)) {
            return VerificationResult(false, "$ERROR_MISSING_REQUIRED_FIELDS$fieldName.$ID")
        }

        fieldValueObject.optString(ID).takeIf { it.isNotEmpty() }?.let { id ->
            if (!Util().isValidUri(id)) {
                return VerificationResult(false, "$ERROR_INVALID_URI$fieldName.$ID")
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

    fun validateNameAndDescription(fieldName: Any, errorMessage: String): VerificationResult {
        return when (fieldName) {
            is String -> VerificationResult(true)
            is JSONArray -> checkForLanguageObject(fieldName, errorMessage)
            else -> VerificationResult(false, "$errorMessage")
        }
    }

    private fun checkForLanguageObject(nameArray: JSONArray, errorMessage: String): VerificationResult {
        for (i in 0 until nameArray.length()) {
            val nameObject = nameArray.getJSONObject(i)
            if (!nameObject.has(LANGUAGE)) {
                return VerificationResult(false, "$errorMessage")
            }
        }
        return VerificationResult(true)
    }


}