import {Errors, Fields} from "../constant/ValidatorConstants.js";
import {
    DataModel,
    getContextVersion,
    validateCredentialSubject, validateFieldsWithID, validateFieldsWithType, validateID, validateIssuer,
    validateMandatoryFields, validateNameAndDescription, validateProof, validateType, verificationFailure, verificationSuccess
} from "./ValidationHelper.js";
import {ValidationError} from "./ValidationError.js";
import {isVCExpired, validateV1SpecificDateFields, validateV2SpecificDateFields} from "./DateUtils.js";
import {isEmptyStringOrEmptyObject} from "./Utils.js";


const commonMandatoryFields = [Fields.CONTEXT, Fields.TYPE, Fields.CREDENTIAL_SUBJECT, Fields.PROOF, Fields.ISSUER]

export const validate = (credential) => {
    try {
        if(isEmptyStringOrEmptyObject(credential)) {
            throw new ValidationError(
                Errors.ERROR_EMPTY_VC_JSON);
        }

        let contextVersion = getContextVersion(credential)

        switch (contextVersion){
            case DataModel.DATA_MODEL_1_1 : {
                v1SpecificFieldsValidation(credential)
                commonValidations(credential)
                const expirationMessage = (credential.hasOwnProperty(Fields.EXPIRATION_DATE) && isVCExpired(credential[Fields.EXPIRATION_DATE]))
                    ? Errors.ERROR_VC_EXPIRED
                    : "";
                return verificationSuccess(expirationMessage)
            }
            case DataModel.DATA_MODEL_2_0: {
                v2SpecificFieldsValidation(credential)
                commonValidations(credential)
                const expirationMessage = (credential.hasOwnProperty(Fields.VALID_UNTIL) && isVCExpired(credential[Fields.VALID_UNTIL]))
                    ? Errors.ERROR_VC_EXPIRED
                    : "";
                return verificationSuccess(expirationMessage)
            }
        }

    } catch (error){
        if(error instanceof ValidationError){
            return verificationFailure(`${error.message}`)
        } else {
            return verificationFailure(`${Errors.EXCEPTION_DURING_VALIDATION}${error.message}`)
        }

    }

}

const v1SpecificFieldsValidation = (credential) => {
    const v1specificMandatoryFields = [...commonMandatoryFields, Fields.ISSUANCE_DATE];
    validateMandatoryFields(credential, v1specificMandatoryFields);
    validateV1SpecificDateFields(credential);

    const allFieldsWithTypeAndId = [
        Fields.CREDENTIAL_STATUS,
        Fields.EVIDENCE,
        Fields.TERMS_OF_USE,
        Fields.REFRESH_SERVICE,
        Fields.CREDENTIAL_SCHEMA,
        Fields.PROOF
    ];

    validateFieldsWithType(credential, allFieldsWithTypeAndId);
    validateFieldsWithID(credential, allFieldsWithTypeAndId, [
        Fields.CREDENTIAL_STATUS,
        Fields.REFRESH_SERVICE,
        Fields.CREDENTIAL_SCHEMA
    ]);
};

const v2SpecificFieldsValidation = (credential) => {
    const v2specificMandatoryFields = [ ...commonMandatoryFields]
    validateMandatoryFields(credential, v2specificMandatoryFields)

    validateV2SpecificDateFields(credential)

    validateNameAndDescription(credential)

    const allFieldsWithTypeAndId = [
        Fields.CREDENTIAL_STATUS,
        Fields.EVIDENCE,
        Fields.TERMS_OF_USE,
        Fields.REFRESH_SERVICE,
        Fields.CREDENTIAL_SCHEMA,
        Fields.PROOF
    ];
    validateFieldsWithType(credential, allFieldsWithTypeAndId)

    const v2IDMandatoryFields = [
        Fields.CREDENTIAL_SCHEMA
    ]
    validateFieldsWithID(credential, allFieldsWithTypeAndId, v2IDMandatoryFields)
}

const commonValidations = (credential) => {

    validateType(credential)

    validateID(credential)

    validateIssuer(credential)

    validateProof(credential)

    validateCredentialSubject(credential)


}





