import {ContextUrls, Errors, Fields, VERIFIABLE_CREDENTIAL} from "../constant/ValidatorConstants.js";
import {ValidationError} from "./ValidationError.js";
import jws from "jws";
import {getId, isNotNullOrEmpty, isObject, isValidURI} from "./Utils.js";

export const DataModel = {
    DATA_MODEL_1_1: "DATA_MODEL_1_1",
    DATA_MODEL_2_0: "DATA_MODEL_2_0"
};

export const getContextVersion = (credential) => {
    if (credential.hasOwnProperty(Fields.CONTEXT)) {
        const contextArray = credential[Fields.CONTEXT];
        const contextUrl = contextArray[0]; // Get the first element of the context array

        switch (contextUrl) {
            case ContextUrls.CREDENTIALS_CONTEXT_V1_URL:
                return DataModel.DATA_MODEL_1_1;
            case ContextUrls.CREDENTIALS_CONTEXT_V2_URL:
                return DataModel.DATA_MODEL_2_0;
            default:
                throw new ValidationError(Errors.ERROR_CONTEXT_FIRST_LINE)
        }
    } else {
        throw new ValidationError(`${Errors.ERROR_MISSING_REQUIRED_FIELDS}${Fields.CONTEXT}`)
    }
}

export const validateMandatoryFields = (credential, mandatoryFields) => {
    for (const field of mandatoryFields) {
        if (!(field in credential) || credential[field] === undefined) {

            throw new ValidationError(`${Errors.ERROR_MISSING_REQUIRED_FIELDS}${field}`);
        }
    }
}

export const validateCredentialSubject = (credential) => {
    const credentialSubject = credential[Fields.CREDENTIAL_SUBJECT];

    if (Array.isArray(credentialSubject)) {
        return credentialSubject.map(subject => _checkCredentialSubject({ subject }));
    } else if(isObject(credentialSubject)) {
        return _checkCredentialSubject({ subject: credentialSubject });
    } else {
        throw new ValidationError(`${Errors.ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT}`);
    }
}

export const _checkCredentialSubject = ({subject}) => {
    if(subject.id && !isValidURI(subject.id)) {
        throw new ValidationError(`${Errors.ERROR_INVALID_URI}${Fields.CREDENTIAL_SUBJECT}.${Fields.ID}`)
    }
}

export const validateIssuer = (credential) => {
    if(credential.hasOwnProperty(Fields.ISSUER)){
        const issuerId = getId(credential[Fields.ISSUER])
        if(issuerId == null || !isValidURI(issuerId)){
            throw new ValidationError(`${Errors.ERROR_INVALID_URI}${Fields.ISSUER}.${Fields.ID}`)
        }
    }
}

export const validateID = (credential) => {
    if(credential.hasOwnProperty(Fields.ID)){
        if(!isValidURI(credential[Fields.ID])){
            throw new ValidationError(`${Errors.ERROR_INVALID_URI}${Fields.ID}`)
        }
    }
}

export const validateType = (credential) => {
    if(credential.hasOwnProperty(Fields.TYPE)){
        if(!credential[Fields.TYPE] || !(credential[Fields.TYPE].length > 0) || (!credential[Fields.TYPE].includes(VERIFIABLE_CREDENTIAL))){
            throw new ValidationError(`${Errors.ERROR_TYPE_VERIFIABLE_CREDENTIAL}`)
        }
    }
}

export const validateProof = (credential) => {
    if(credential.hasOwnProperty(Fields.PROOF)){
        if(isNotNullOrEmpty(credential[Fields.PROOF])){
            const proofType = credential[Fields.PROOF][Fields.TYPE]
            if(credential[Fields.PROOF].hasOwnProperty(Fields.JWS)){
                if(isNotNullOrEmpty(proofType) && !PROOF_TYPES_SUPPORTED.includes(proofType)){
                    throw new ValidationError(`${Errors.ERROR_PROOF_TYPE_NOT_SUPPORTED}`)
                }
                const { header } = jws.decode(credential.proof.jws);
                if(!ALGORITHMS_SUPPORTED.includes(header.alg)){
                    throw new ValidationError(`${Errors.ERROR_ALGORITHM_NOT_SUPPORTED}`)
                }
            }
        }
    }
}

export const validateNameAndDescription = (credential)  => {
    const nameDescriptionList = [
        { field: `${Fields.NAME}`, error: `${Errors.ERROR_NAME}` },
        { field: `${Fields.DESCRIPTION}`, error:`${Errors.ERROR_DESCRIPTION}` },
    ];

    nameDescriptionList.forEach(({ field, error }) => {
        if (credential.hasOwnProperty(field)) {
            const fieldValue = credential[field];
            if (typeof fieldValue === 'string') {
                return;
            } else if (Array.isArray(fieldValue)) {
                checkForLanguageObject(fieldValue, error);
            } else {
                throw new ValidationError(error);
            }
        }
    });
}

export const checkForLanguageObject = (nameArray, errorMessage) => {
    nameArray.forEach((nameObject) => {
        if (!nameObject.hasOwnProperty(Fields.LANGUAGE)) {
            throw new ValidationError(errorMessage);
        }
    });
}


export const validateFieldsWithID = (credential, allFieldsWithTypeAndId, idMandatoryFields) => {
    allFieldsWithTypeAndId.forEach((fieldName) => {
        const fieldValue = credential[fieldName];
        if (fieldValue !== undefined) {
            if (Array.isArray(fieldValue)) {
                fieldValue.forEach((item) => validateSingleIDObject(fieldName, item, idMandatoryFields));
            } else if (typeof fieldValue === 'object' && fieldValue !== null) {
                validateSingleIDObject(fieldName, fieldValue, idMandatoryFields);
            } else {
                throw new ValidationError(`${Errors.ERROR_INVALID_FIELD}${fieldName}`);
            }
        }
    });
};

const validateSingleIDObject = (fieldName, fieldValueObject, idMandatoryFields) => {
    if (idMandatoryFields.includes(fieldName) && !fieldValueObject.hasOwnProperty(Fields.ID)) {
        throw new ValidationError(`${Errors.ERROR_MISSING_REQUIRED_FIELDS}${fieldName}.${Fields.ID}`);
    }

    const id = fieldValueObject[Fields.ID];
    if (id && !isValidURI(id)) {
        throw new ValidationError(`${Errors.ERROR_INVALID_URI}${fieldName}.${Fields.ID}`);
    }
};

export const validateFieldsWithType = (credential, typeMandatoryFields) => {
    typeMandatoryFields.forEach((fieldName) => {
        const fieldValue = credential[fieldName];
        if (fieldValue !== undefined) {
            if (Array.isArray(fieldValue)) {
                fieldValue.forEach((item) => validateSingleTypeObject(fieldName, item));
            } else if (typeof fieldValue === 'object' && fieldValue !== null) {
                validateSingleTypeObject(fieldName, fieldValue);
            } else {
                throw new ValidationError(`${Errors.ERROR_INVALID_FIELD}${fieldName}`);
            }
        }
    });
};

const validateSingleTypeObject = (fieldName, fieldValueObject) => {
    if (!fieldValueObject.hasOwnProperty(Fields.TYPE)) {
        throw new ValidationError(`${Errors.ERROR_MISSING_REQUIRED_FIELDS}${fieldName}.${Fields.TYPE}`);
    }
};



export const validationSuccess = (message) => ({
    verificationStatus: true,
    verificationErrorMessage: message ? message: ""
});

export const validationFailure = (error) => ({
    verificationStatus: false,
    verificationErrorMessage: error
});

const ALGORITHMS_SUPPORTED = ["PS256", "RS256"]
const PROOF_TYPES_SUPPORTED = ["RsaSignature2018"]

