package io.mosip.vercred.vcverifier.credentialverifier.validator

import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SCHEMA
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CONTEXT_FIRST_LINE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VC_EXPIRED
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
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.Util
import io.mosip.vercred.vcverifier.utils.ValidationHelper
import org.bitcoinj.core.VerificationException
import org.json.JSONObject

class LdpValidator {

    private val commonMandatoryFields = listOf(
        CONTEXT,
        TYPE,
        CREDENTIAL_SUBJECT,
        ISSUER,
        PROOF
    )

    private val commonIDMandatoryFields = listOf(
        CREDENTIAL_SCHEMA
    )

    //All Fields has Type Property as mandatory with few fields as ID as optional.
    private val fieldsWithIDAndType = listOf(
        PROOF,
        CREDENTIAL_STATUS,
        EVIDENCE,
        CREDENTIAL_SCHEMA,
        REFRESH_SERVICE,
        TERMS_OF_USE
    )

    private val validationHelper = ValidationHelper()
    private val dateUtils = DateUtils()

    fun validate(credential: String): VerificationResult {
        try {
            if (credential.isEmpty()) {
                throw ValidationException(ERROR_EMPTY_VC_JSON)
            }

            val vcJsonObject = JSONObject(credential)

            val contextVersion = Util().getContextVersion(vcJsonObject)
                ?: throw ValidationException("$ERROR_MISSING_REQUIRED_FIELDS$CONTEXT")
            when (contextVersion) {
                DATA_MODEL.DATA_MODEL_1_1 -> {
                    validateV1SpecificFields(vcJsonObject)
                    validateCommonFields(vcJsonObject)
                    val expirationMessage = if (vcJsonObject.has(EXPIRATION_DATE) && dateUtils.isVCExpired(vcJsonObject.optString(
                            EXPIRATION_DATE))) ERROR_VC_EXPIRED else ""
                    return VerificationResult(true, expirationMessage)
                }
                DATA_MODEL.DATA_MODEL_2_0 -> {
                    validateV2SpecificFields(vcJsonObject)
                    validateCommonFields(vcJsonObject)
                    val expirationMessage = if (vcJsonObject.has(VALID_UNTIL) && dateUtils.isVCExpired(vcJsonObject.optString(VALID_UNTIL))) ERROR_VC_EXPIRED else ""
                    return VerificationResult(true, expirationMessage)
                }
                else -> {
                    throw ValidationException(ERROR_CONTEXT_FIRST_LINE)
                }
            }

        }
        catch (e: ValidationException) {
            return VerificationResult(false, "${e.message}")
        }
        catch (e: Exception) {
            return VerificationResult(false, "${EXCEPTION_DURING_VALIDATION}${e.message}")
        }

    }

    //Validation for Data Model 1.1
    private fun validateV1SpecificFields(vcJsonObject: JSONObject) {

        val v1SpecificMandatoryFields = listOf(
            ISSUANCE_DATE
        )

        val v1SpecificIDMandatoryFields = listOf(
            REFRESH_SERVICE,
            CREDENTIAL_STATUS
        )

        validationHelper.checkMandatoryFields(vcJsonObject, commonMandatoryFields+v1SpecificMandatoryFields)

        dateUtils.validateV1DateFields(vcJsonObject)

        fieldsWithIDAndType.forEach { field ->
            if(vcJsonObject.has(field)){
                validationHelper.validateFieldsByIdAndType(
                    vcJsonObject = vcJsonObject,
                    fieldName = field,
                    idMandatoryFields = commonIDMandatoryFields+v1SpecificIDMandatoryFields
                )
            }
        }

    }

    //Validation for Data Model 2.0
    private fun validateV2SpecificFields(vcJsonObject: JSONObject){

        validationHelper.checkMandatoryFields(vcJsonObject, commonMandatoryFields)

        dateUtils.validateV2DateFields(vcJsonObject)

        fieldsWithIDAndType.forEach { field ->
            if(vcJsonObject.has(field)){
                validationHelper.validateFieldsByIdAndType(vcJsonObject = vcJsonObject,
                    fieldName = field,
                    idMandatoryFields = commonIDMandatoryFields
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



    companion object{
        const val CREDENTIALS_CONTEXT_V1_URL = "https://www.w3.org/2018/credentials/v1"
        const val CREDENTIALS_CONTEXT_V2_URL = "https://www.w3.org/ns/credentials/v2"
        const val VERIFIABLE_CREDENTIAL = "VerifiableCredential"
    }
}
