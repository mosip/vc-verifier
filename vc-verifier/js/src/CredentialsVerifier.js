import jws from 'jws';
import crypto from 'crypto';
import { Constants } from './constant/Constants.js';
import { getJwsSigningInput } from './utils/JwsSigningInput.js';
import { URDNA2015Canonicalizer } from './utils/URDNA2015Canonicalizer.js';
import axios from 'axios';
import {validate} from "./validator/LdpValidator.js";
import {Errors} from "./constant/ValidatorConstants.js";
import {isNotNullOrEmpty} from "./validator/Utils.js";
import {preProcessVerifiableCredential} from "./utils/CredentialUtils.js";


const getPublicKeyFromVerificationMethod = async (url) => {
    let response = await axios.get(url);
    response = response.data;
    const publicKeyPem = response['publicKeyPem'];
    const publicKeyObject = crypto.createPublicKey(
        {
            key: publicKeyPem,
            format: 'pem',
            type: 'spki'
        }
    );
    if (!publicKeyObject)
        throw new Error("Error while creating Public Key Object");
    return publicKeyObject;
}

const verifyCredentialSignature = (jwsHeaderAlgoName, publicKey, actualData, signature) => {
    let isVerified = false;
    if (jwsHeaderAlgoName === Constants.JWS_PS256_SIGN_ALGO_CONST) {
        isVerified = crypto.verify(
            'RSA-SHA256',
            actualData,
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            },
            signature
        );
    }
    else if (jwsHeaderAlgoName === Constants.JWS_RS256_SIGN_ALGO_CONST) {
        isVerified = crypto.verify('RSA-SHA256', actualData, publicKey, signature);
    }
    else {
        throw new Error('Verification algorithm not supported');
    }
    return isVerified;
}

/**
 * @deprecated This method has been deprecated because it is not extensible for future use cases of supporting different VC format's verification
 * Please use verify(credentials, format) instead, which is designed for supporting different VC formats.
 * This method only supports LDP VC format
 */
export const verifyCredentials = async (credential) => {
    try {
        preProcessVerifiableCredential(credential);
        return await verifySignature(credential)
    } catch (error) {
        throw error;
    }
}

/**
 * Validates the provided credentials against the specified format and Verifies the Signature.
 *
 * @param {Object} credential - The credentials to verify, containing necessary fields.
 * @param {string} credentialFormat - The expected format for the credentials (e.g., 'ldp').
 * @returns {Promise<Object>} The result of the verification, including a status and any relevant messages.
 */
export const verify = async (credential, credentialFormat) => {
    try {
        const validationMessage = validate(credential)

        if(isNotNullOrEmpty(validationMessage) && (validationMessage !== Errors.ERROR_VC_EXPIRED)){
            verificationFailure(validationMessage)
        }
        const verificationResult = await verifySignature(credential)
        if(!verificationResult) {
            return verificationFailure(`${Errors.SIGNATURE_VERIFICATION_FAILED}`)
        }
        return verificationSuccess(validationMessage)

    } catch (error) {
        return verificationFailure(`${Errors.EXCEPTION_DURING_VERIFICATION}${error.message}`)
    }
}

const verifySignature = async (credential) => {
    const { signature, header } = jws.decode(credential.proof.jws);
    const decodedSignature = Buffer.from(signature, 'base64');
    const publicKeyObject = await getPublicKeyFromVerificationMethod(credential.proof.verificationMethod);
    const canonicalisedCredential = await URDNA2015Canonicalizer(credential);
    const inputData = getJwsSigningInput(header, canonicalisedCredential);
    return verifyCredentialSignature(header.alg, publicKeyObject, inputData, decodedSignature);
}

const verificationSuccess = (message) => ({
    verificationStatus: true,
    verificationMessage: message ? message: ""
});

const verificationFailure = (errorMessage) => ({
    verificationStatus: false,
    verificationMessage: errorMessage
});