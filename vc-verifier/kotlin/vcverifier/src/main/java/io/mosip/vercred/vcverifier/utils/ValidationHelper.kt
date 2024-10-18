package io.mosip.vercred.vcverifier.utils

import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ALGORITHMS_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.DESCRIPTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ALGORITHM_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_DESCRIPTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_FIELD
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_PROOF_TYPE_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_TYPE_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.JWS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.LANGUAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF_TYPES_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.credentialverifier.validator.LdpValidator.Companion.VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.exception.ValidationException
import org.json.JSONArray
import org.json.JSONObject

class ValidationHelper {


    fun checkMandatoryFields(vcJsonObject: JSONObject, fields: List<String>) {

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
                    throw ValidationException( "$ERROR_MISSING_REQUIRED_FIELDS$field")
                }
            }
        }
    }
    fun validateCredentialSubject(vcJsonObject: JSONObject) {
        val credentialSubject = vcJsonObject.get(CREDENTIAL_SUBJECT)
        validateJsonObjectOrArray(credentialSubject, ::validateSingleCredentialObject, "$ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT")
    }

    fun validateFieldsByIdAndType(vcJsonObject: JSONObject, fieldName: String, idMandatoryFields: List<String>) {
        val fieldValue = vcJsonObject.get(fieldName)
        validateJsonObjectOrArray(fieldValue, { obj -> validateSingleObject(fieldName, obj, idMandatoryFields) }, "$ERROR_INVALID_FIELD$fieldName")
    }

    private fun validateJsonObjectOrArray(
        value: Any,
        validator: (JSONObject) -> VerificationResult,
        errorMessage: String
    ) {
        when (value) {
            is JSONArray -> {
                for (i in 0 until value.length()) {
                    val jsonObject = value.getJSONObject(i)
                    val result = validator(jsonObject)
                    if (!result.verificationStatus) throw ValidationException(errorMessage)
                }
            }
            is JSONObject -> validator(value)
            else -> throw ValidationException(errorMessage)
        }
    }

    private fun validateSingleCredentialObject(credentialSubjectObject: JSONObject): VerificationResult {
        if (credentialSubjectObject.has(ID) && !Util().isValidUri(credentialSubjectObject.optString(ID))) {
            throw ValidationException("$ERROR_INVALID_URI$CREDENTIAL_SUBJECT.$ID")
        }
        return VerificationResult(true)
    }

    private fun validateSingleObject(fieldName: String, fieldValueObject: JSONObject, idMandatoryFields: List<String>): VerificationResult {
        if (!fieldValueObject.has(TYPE)) {
            return throw ValidationException( "$ERROR_MISSING_REQUIRED_FIELDS$fieldName.$TYPE")
        }

        val isIDMandatoryField = idMandatoryFields.contains(fieldName)
        if (isIDMandatoryField && !fieldValueObject.has(ID)) {
            return throw ValidationException("$ERROR_MISSING_REQUIRED_FIELDS$fieldName.$ID")
        }

        fieldValueObject.optString(ID).takeIf { it.isNotEmpty() }?.let { id ->
            if (!Util().isValidUri(id)) {
                return throw ValidationException( "$ERROR_INVALID_URI$fieldName.$ID")
            }
        }

        return VerificationResult(true)
    }



    fun validateProof(vcJsonString: String) {
        val vcJsonObject = JSONObject(vcJsonString)

        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(vcJsonString)
        val ldProof : LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)

        if(vcJsonObject.getJSONObject(PROOF).has(JWS)){
            val jwsToken: String = ldProof.jws
            val algorithmName: String = JWSObject.parse(jwsToken).header.algorithm.name
            if(jwsToken.isNullOrEmpty() || !ALGORITHMS_SUPPORTED.contains(algorithmName)){
                throw ValidationException( ERROR_ALGORITHM_NOT_SUPPORTED )
            }
        }

        val ldProofType: String = ldProof.type
        if (!PROOF_TYPES_SUPPORTED.contains(ldProofType)) {
            throw ValidationException( ERROR_PROOF_TYPE_NOT_SUPPORTED)
        }
    }

    fun validateId(vcJsonObject: JSONObject){
        if(vcJsonObject.has(ID)){
            if(!Util().isValidUri(vcJsonObject.getString(ID))){
                throw ValidationException("$ERROR_INVALID_URI$ID")
            }
        }

    }

    fun validateType(vcJsonObject: JSONObject){

        if(vcJsonObject.has(TYPE)){
            vcJsonObject.optJSONArray(TYPE)?.let { types ->
                if (!Util().jsonArrayToList(types).contains(VERIFIABLE_CREDENTIAL)) {
                    throw ValidationException(ERROR_TYPE_VERIFIABLE_CREDENTIAL)
                }
            }
        }

    }

    fun validateIssuer(vcJsonObject: JSONObject){
        if(vcJsonObject.has(ISSUER)){
            val issuerId = Util().getId(vcJsonObject.get(ISSUER))
            if(issuerId == null || !Util().isValidUri(issuerId)) {
                throw ValidationException( "$ERROR_INVALID_URI$ISSUER")
            }
        }
    }

    fun validateNameAndDescription(vcJsonObject: JSONObject) {

        val nameDescriptionList: List<Pair<String, String>> = listOf(
            NAME to ERROR_NAME,
            DESCRIPTION to ERROR_DESCRIPTION
        )

        nameDescriptionList.forEach { fieldPair ->

            if(vcJsonObject.has(fieldPair.first)){
                when (val fieldValue = vcJsonObject.get(fieldPair.first)) {
                    is String -> return
                    is JSONArray -> checkForLanguageObject(fieldValue, fieldPair.second)
                    else -> throw ValidationException(fieldPair.second)
                }
            }

        }

    }

    private fun checkForLanguageObject(nameArray: JSONArray, errorMessage: String) {
        for (i in 0 until nameArray.length()) {
            val nameObject = nameArray.getJSONObject(i)
            if (!nameObject.has(LANGUAGE)) {
                throw ValidationException(errorMessage)
            }
        }
    }


}