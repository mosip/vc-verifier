package io.mosip.vercred.vcverifier.credentialverifier.verifiablecredential.validator

import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ALGORITHMS_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ALGORITHM_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CONTEXT_FIRST_LINE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EXPIRATION_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ISSUANCE_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_PROOF_TYPE_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_TYPE_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.JWS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF_TYPES_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.data.VerificationResult
import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONObject

class LdpValidator {

    private val requiredFields = listOf(
        ID,
        PROOF,
        "$PROOF.$TYPE",
        ISSUER,
        CONTEXT,
        TYPE,
        CREDENTIAL_SUBJECT,
        ISSUANCE_DATE
    )

    fun validate(credential: String): VerificationResult {

        try {
            if (credential.isNullOrEmpty()) {
                return VerificationResult(false, ERROR_EMPTY_VC_JSON)
            }

            val vcJsonObject = JSONObject(credential)

            val mandatoryCheck = checkMandatoryFields(vcJsonObject, requiredFields)
            if (!mandatoryCheck.verificationStatus) {
                return mandatoryCheck
            }

            val invalidCheck = checkInvalidFields(vcJsonObject)
            if (!invalidCheck.verificationStatus) {
                return invalidCheck
            }

            val isValidProofType = validateProof(credential)
            if (!isValidProofType.verificationStatus) {
                return isValidProofType
            }


            return handleExpiredVC(vcJsonObject)
        } catch (e: Exception){
            return  VerificationResult(false, "$EXCEPTION_DURING_VALIDATION${e.message.toString()}")
        }
    }

    private fun checkMandatoryFields(vcJsonObject: JSONObject, fields: List<String>): VerificationResult {

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

    private fun checkInvalidFields(vcJsonObject: JSONObject): VerificationResult {

        val firstContext = vcJsonObject.getJSONArray(CONTEXT).getString(0)
        if (firstContext != CREDENTIALS_CONTEXT_V1_URL) {
            return VerificationResult(false, ERROR_CONTEXT_FIRST_LINE)
        }

        val issuer = vcJsonObject.optString(ISSUER)
        if (!Util().isValidUri(issuer)) {
            return VerificationResult(false, "$ERROR_INVALID_URI$ISSUER")
        }

        listOf(
            ISSUANCE_DATE to ERROR_ISSUANCE_DATE_INVALID,
            EXPIRATION_DATE to ERROR_EXPIRATION_DATE_INVALID
        ).forEach { (dateKey, errorMessage) ->
            if (vcJsonObject.has(dateKey) && !Util().isValidDate(vcJsonObject.get(dateKey).toString())) {
                return VerificationResult(false, errorMessage)
            }
        }

        vcJsonObject.optJSONArray(TYPE)?.let { types ->
            if (!Util().jsonArrayToList(types).contains(VERIFIABLE_CREDENTIAL)) {
                return VerificationResult(false, ERROR_TYPE_VERIFIABLE_CREDENTIAL)
            }
        }

        return VerificationResult(true)
    }

    private fun handleExpiredVC(vcJsonObject: JSONObject): VerificationResult {
        val expirationDate = vcJsonObject.optString(EXPIRATION_DATE)
        if (expirationDate.isNotEmpty() && Util().isDateExpired(expirationDate)) {
            return VerificationResult(true, ERROR_VC_EXPIRED)
        }
        return VerificationResult(true)
    }


    private fun validateProof(vcJsonString: String): VerificationResult{
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

    companion object{
        const val CREDENTIALS_CONTEXT_V1_URL = "https://www.w3.org/2018/credentials/v1"
        const val VERIFIABLE_CREDENTIAL = "VerifiableCredential"
    }
}