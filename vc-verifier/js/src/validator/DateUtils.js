import {Errors, Fields} from "../constant/ValidatorConstants.js";
import {ValidationError} from "./ValidationError.js";


export const validateV1SpecificDateFields = (credential) => {
    const dateFields = [Fields.ISSUANCE_DATE, Fields.EXPIRATION_DATE]
    const errorMessage = {
        [Fields.ISSUANCE_DATE] : Errors.ERROR_ISSUANCE_DATE_INVALID,
        [Fields.EXPIRATION_DATE]: Errors.ERROR_EXPIRATION_DATE_INVALID
    }

    for (let i = 0; i < dateFields.length; i++) {
        const field = dateFields[i];
        if (credential.hasOwnProperty(field) && !isValidDate(credential[field])) {
            throw new ValidationError(errorMessage[field])
        }
    }

    const issuanceDate = new Date(credential[Fields.ISSUANCE_DATE])
    if(!isDatePassedCurrentDate(issuanceDate)){
        throw new ValidationError(`${Errors.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE}`)
    }

}


export const validateV2SpecificDateFields = (credential) => {
    const dateFields = [Fields.VALID_FROM, Fields.VALID_UNTIL]
    const errorMessage = {
        [Fields.VALID_FROM] : Errors.ERROR_VALID_FROM_INVALID,
        [Fields.VALID_UNTIL]: Errors.ERROR_VALID_UNTIL_INVALID
    }

    for (let i = 0; i < dateFields.length; i++) {
        const field = dateFields[i];
        if (credential.hasOwnProperty(field) && !isValidDate(credential[field])) {
            throw new ValidationError(errorMessage[field])
        }
    }

    const validFrom = new Date(credential[Fields.VALID_FROM])
    if(!isDatePassedCurrentDate(validFrom)){
        throw new ValidationError(`${Errors.ERROR_CURRENT_DATE_BEFORE_VALID_FROM}`)
    }

}

export const isVCExpired = (inputDate) => {
    return inputDate.trim() !== '' && isDatePassedCurrentDate(inputDate);
}


export const isValidDate = (dateValue) => {
    const dateFormatRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
    return dateFormatRegex.test(dateValue)
}

export const  isDatePassedCurrentDate = (inputDateString) => {
    try {
        const inputDate = new Date(inputDateString);

        if (isNaN(inputDate)) {
            return false;
        }

        const currentDate = new Date();
        return inputDate < currentDate;
    } catch (e) {
        return false;
    }
}