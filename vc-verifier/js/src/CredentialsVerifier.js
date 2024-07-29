import jws from 'jws';
import crypto from 'crypto';
import { Constants } from './constant/Constants.js';
import { getJwsSigningInput } from './utils/JwsSigningInput';
import { URDNA2015Canonicalizer } from './utils/URDNA2015Canonicalizer';
import { preProcessVerifiableCredential } from './utils/CredentialUtils';
import axios from 'axios';
import {PS256VC} from "./vc/PS256VCOriginal.js";


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

export const verifyCredentials = async (credential) => {
    try {
        preProcessVerifiableCredential(credential);
        const { signature, header } = jws.decode(credential.proof.jws);
        const decodedSignature = Buffer.from(signature, 'base64');
        const publicKeyObject = await getPublicKeyFromVerificationMethod(credential.proof.verificationMethod);
        const canonicalisedCredential = await URDNA2015Canonicalizer(credential);
        const inputData = getJwsSigningInput(header, canonicalisedCredential);
        return verifyCredentialSignature(header.alg, publicKeyObject, inputData, decodedSignature);
    } catch (error) {
        throw error;
    }
}