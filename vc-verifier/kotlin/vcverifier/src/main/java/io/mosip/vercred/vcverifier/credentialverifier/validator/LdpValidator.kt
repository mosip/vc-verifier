package io.mosip.vercred.vcverifier.credentialverifier.validator

import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SCHEMA
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_GENERIC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_CONTEXT_FIRST_LINE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EVIDENCE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.REFRESH_SERVICE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TERMS_OF_USE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_UNTIL
import io.mosip.vercred.vcverifier.data.DATA_MODEL
import io.mosip.vercred.vcverifier.data.ValidationStatus
import io.mosip.vercred.vcverifier.exception.ValidationException
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
        PROOF
    )

    //All Fields has Type Property as mandatory with few fields as ID as mandatory.
    private val allFieldsWithIDAndType = listOf(
        PROOF,
        CREDENTIAL_STATUS,
        EVIDENCE,
        CREDENTIAL_SCHEMA,
        REFRESH_SERVICE,
        TERMS_OF_USE
    )

    private val validationHelper = ValidationHelper()
    private val dateUtils = DateUtils

    fun validate(credential: String): ValidationStatus {
        try {
            if (credential.isEmpty()) {
                throw ValidationException(ERROR_MESSAGE_EMPTY_VC_JSON, ERROR_CODE_EMPTY_VC_JSON)
            }

            val vcJsonObject = JSONObject(credential)

            val contextVersion = Util.getContextVersion(vcJsonObject)
                ?: throw ValidationException("$ERROR_MISSING_REQUIRED_FIELDS$CONTEXT", "${ERROR_CODE_MISSING}${CONTEXT.uppercase()}")
            when (contextVersion) {
                DATA_MODEL.DATA_MODEL_1_1 -> {
                    validateV1SpecificFields(vcJsonObject)
                    validateCommonFields(vcJsonObject)
                    val expirationMessage = if (vcJsonObject.has(EXPIRATION_DATE) && dateUtils.isVCExpired(vcJsonObject.optString(
                            EXPIRATION_DATE))) ERROR_MESSAGE_VC_EXPIRED else ""
                    val verificationStatusCode = if (vcJsonObject.has(EXPIRATION_DATE) && dateUtils.isVCExpired(vcJsonObject.optString(
                            EXPIRATION_DATE))) ERROR_CODE_VC_EXPIRED else ""
                    return ValidationStatus(expirationMessage, verificationStatusCode)
                }
                DATA_MODEL.DATA_MODEL_2_0 -> {
                    validateV2SpecificFields(vcJsonObject)
                    validateCommonFields(vcJsonObject)
                    val expirationMessage = if (vcJsonObject.has(VALID_UNTIL) && dateUtils.isVCExpired(vcJsonObject.optString(VALID_UNTIL))) ERROR_MESSAGE_VC_EXPIRED else ""
                    val verificationStatusCode = if (vcJsonObject.has(VALID_UNTIL) && dateUtils.isVCExpired(vcJsonObject.optString(
                            VALID_UNTIL))) ERROR_CODE_VC_EXPIRED else ""
                    return ValidationStatus(expirationMessage, verificationStatusCode)
                }
                else -> {
                    throw ValidationException(ERROR_MESSAGE_CONTEXT_FIRST_LINE, "${ERROR_CODE_INVALID}${CONTEXT.uppercase()}")
                }
            }

        }
        catch (e: ValidationException) {
            return ValidationStatus(e.errorMessage, e.errorCode)
        }
        catch (e: Exception) {
            return ValidationStatus("${EXCEPTION_DURING_VALIDATION}${e.message}", ERROR_CODE_GENERIC)
        }

    }

    //Validation for Data Model 1.1
    private fun validateV1SpecificFields(vcJsonObject: JSONObject) {

        val v1SpecificMandatoryFields = listOf(
            ISSUANCE_DATE
        )

        validationHelper.checkMandatoryFields(vcJsonObject, commonMandatoryFields+v1SpecificMandatoryFields)

        dateUtils.validateV1DateFields(vcJsonObject)

        val v1SpecificIdMandatoryFields = listOf(
            CREDENTIAL_STATUS,
            REFRESH_SERVICE,
            CREDENTIAL_SCHEMA
        )

        allFieldsWithIDAndType.forEach { field ->
            if(vcJsonObject.has(field)){
                validationHelper.validateFieldsByIdAndType(
                    vcJsonObject = vcJsonObject,
                    fieldName = field,
                    idMandatoryFields = v1SpecificIdMandatoryFields
                )
            }
        }

    }

    //Validation for Data Model 2.0
    private fun validateV2SpecificFields(vcJsonObject: JSONObject){

        validationHelper.checkMandatoryFields(vcJsonObject, commonMandatoryFields)

        dateUtils.validateV2DateFields(vcJsonObject)

        val v2SpecificIdMandatoryFields = listOf(
            CREDENTIAL_SCHEMA
        )

        allFieldsWithIDAndType.forEach { field ->
            if(vcJsonObject.has(field)){
                validationHelper.validateFieldsByIdAndType(vcJsonObject = vcJsonObject,
                    fieldName = field,
                    idMandatoryFields = v2SpecificIdMandatoryFields
                )
            }
        }

        validationHelper.validateNameAndDescription(vcJsonObject)


    }

    //Common Validations
    private fun validateCommonFields(vcJsonObject: JSONObject){

        validationHelper.validateCredentialSubject(vcJsonObject)

        validationHelper.validateProof(vcJsonObject.toString())

        validationHelper.validateId(vcJsonObject)

        validationHelper.validateType(vcJsonObject)

        validationHelper.validateIssuer(vcJsonObject)

    }
}
