import { Constants } from "../../src/constant/Constants.js";
import { preProcessVerifiableCredential } from "../../src/utils/CredentialUtils";

describe('preProcessVerifiableCredential', () => {
    it('should process the credential correctly', () => {
        const credential = {
            proof: {
                type: 'RsaSignature2018'
            },
            type: ['VerifiableCredential']
        };

        preProcessVerifiableCredential(credential);
        expect(credential.type).toEqual('VerifiableCredential');
    });

    it('should throw an error if proof is missing', () => {
        const credential = {};
        expect(() => preProcessVerifiableCredential(credential)).toThrow('Proof document is not available in the received credentials.');
    });

    it('should throw an error if the proof type is not matching', () => {
        const credential = {
            proof: { type: 'InvalidSignatureType' },
            type: ['VerifiableCredential']
        };

        expect(() => preProcessVerifiableCredential(credential)).toThrow("Proof Type is not supported. Recevied Type: InvalidSignatureType");
    });

    it('should throw an error if the credential type is not VerifiableCredential', () => {
        const credential = {
            proof: { type: Constants.SIGNATURE_SUITE_TERM },
            type: ['NonVerifiableCredential']
        };

        expect(() => preProcessVerifiableCredential(credential)).toThrow("Credential is not of type Verifiable Credential.");
    });
});