import { Constants } from "../constant/Constants.js";

export const preProcessVerifiableCredential = (credential) => {
    if (!credential["proof"]) {
        throw new Error("Proof document is not available in the received credentials.");
    }
    const jsonLdProof = credential["proof"];
    if (!jsonLdProof?.["type"] || jsonLdProof["type"] !== Constants.SIGNATURE_SUITE_TERM) {
        throw new Error("Proof Type is not supported. Recevied Type: " + jsonLdProof?.["type"]);
    }
    if (!credential["type"].includes('VerifiableCredential')) {
        throw new Error("Credential is not of type Verifiable Credential.")
    }
    credential['type'] = 'VerifiableCredential'

}