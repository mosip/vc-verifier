package io.mosip.vercred.vcverifier.credentialverifier.validator

import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CONTEXT_FIRST_LINE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_TYPE_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_UNTIL
import io.mosip.vercred.vcverifier.data.DATA_MODEL
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.ValidationHelper
import org.json.JSONObject

class LdpValidator {

    private val commonMandatoryFields = listOf(
        CONTEXT,
        TYPE,
        CREDENTIAL_SUBJECT,
        ISSUER,
        PROOF,
        "$PROOF.$TYPE"
    )

    private val v1SpecificMandatoryFields = listOf(
        ISSUANCE_DATE
    )

    private val validatorUtils = ValidationHelper()
    private val dateUtils = DateUtils()

    fun validate(credential: String): VerificationResult {

        if (credential.isNullOrEmpty()) {
            return VerificationResult(false, ERROR_EMPTY_VC_JSON)
        }

        return try {
            val vcJsonObject = JSONObject(credential)
            val contextVersion = Util().getContextVersion(vcJsonObject)
                ?: return VerificationResult(false, "$ERROR_MISSING_REQUIRED_FIELDS$CONTEXT")

            val verificationResult = when (contextVersion) {
                DATA_MODEL.DATA_MODEL_1_1 -> {
                    validateV1Fields(vcJsonObject).also {
                        if (!it.verificationStatus) return it
                    }
                }
                DATA_MODEL.DATA_MODEL_2_0 -> {
                    validateV2Fields(vcJsonObject).also {
                        if (!it.verificationStatus) return it
                    }
                }
                else -> {
                    return VerificationResult(false, "$ERROR_CONTEXT_FIRST_LINE")
                }
            }

            validateCommonFields(vcJsonObject).takeIf { !it.verificationStatus } ?: verificationResult

        } catch (e: Exception) {
            VerificationResult(false, "$EXCEPTION_DURING_VALIDATION${e.message}")
        }
    }

    //Validation for Data Model 1.1
    private fun validateV1Fields(vcJsonObject: JSONObject): VerificationResult {

        validatorUtils.checkMandatoryFields(vcJsonObject, commonMandatoryFields+v1SpecificMandatoryFields).let { mandatoryCheck ->
            if (!mandatoryCheck.verificationStatus) {
                return mandatoryCheck
            }
        }

        val dateValidationResult = dateUtils.validateV1DateFields(vcJsonObject)
        if (!dateValidationResult.verificationStatus) {
            return dateValidationResult
        }

        if(vcJsonObject.has(CREDENTIAL_STATUS)){
            val credentialStatusResult = validatorUtils.validateCredentialStatus(vcJsonObject.get(CREDENTIAL_STATUS), DATA_MODEL.DATA_MODEL_1_1)
            if(!credentialStatusResult.verificationStatus){
                return credentialStatusResult
            }
        }

        val verificationMessage = if (vcJsonObject.has(EXPIRATION_DATE) && dateUtils.isVCExpired(vcJsonObject.optString(
                EXPIRATION_DATE))) ERROR_VC_EXPIRED else ""
        return VerificationResult(true, verificationMessage)
    }

    //Validation for Data Model 2.0
    private fun validateV2Fields(vcJsonObject: JSONObject): VerificationResult{

        validatorUtils.checkMandatoryFields(vcJsonObject, commonMandatoryFields).let { mandatoryCheck ->
            if (!mandatoryCheck.verificationStatus) {
                return mandatoryCheck
            }
        }

        val dateValidationResult = dateUtils.validateV2DateFields(vcJsonObject)
        if (!dateValidationResult.verificationStatus) {
            return dateValidationResult
        }

        if(vcJsonObject.has(CREDENTIAL_STATUS)){
            val credentialStatusResult = validatorUtils.validateCredentialStatus(vcJsonObject.get(CREDENTIAL_STATUS), DATA_MODEL.DATA_MODEL_2_0)
            if(!credentialStatusResult.verificationStatus){
                return credentialStatusResult
            }
        }

        val verificationMessage = if (vcJsonObject.has(VALID_UNTIL) && dateUtils.isVCExpired(vcJsonObject.optString(VALID_UNTIL))) ERROR_VC_EXPIRED else ""
        return VerificationResult(true, verificationMessage)
    }

    //Common Validations
    private fun validateCommonFields(vcJsonObject: JSONObject): VerificationResult{

        validatorUtils.validateProof(vcJsonObject.toString()).let { proofValidationResult ->
            if (!proofValidationResult.verificationStatus) {
                return proofValidationResult
            }
        }

        if(vcJsonObject.has(ID)){
            val id = vcJsonObject.getString(ID)
            if(!Util().isValidUri(id)){
                return VerificationResult(false, "$ERROR_INVALID_URI$ID")
            }
        }

        if(vcJsonObject.has(ISSUER)){
            val issuerId = Util().getId(vcJsonObject.get(ISSUER))
            if(issuerId == null || !Util().isValidUri(issuerId)) {
                return VerificationResult(false, "$ERROR_INVALID_URI$ISSUER")
            }
        }

        vcJsonObject.optJSONArray(TYPE)?.let { types ->
            if (!Util().jsonArrayToList(types).contains(VERIFIABLE_CREDENTIAL)) {
                return VerificationResult(false, ERROR_TYPE_VERIFIABLE_CREDENTIAL)
            }
        }

        return VerificationResult(true)
    }



    companion object{
        const val CREDENTIALS_CONTEXT_V1_URL = "https://www.w3.org/2018/credentials/v1"
        const val CREDENTIALS_CONTEXT_V2_URL = "https://www.w3.org/ns/credentials/v2"
        const val VERIFIABLE_CREDENTIAL = "VerifiableCredential"
    }
}
