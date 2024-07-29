import jws from 'jws';
import crypto from 'crypto';
import axios from 'axios';
import { jest } from '@jest/globals';
import jsonld from 'jsonld';
import { verifyCredentials } from "../src/CredentialsVerifier";


jest.mock('jws');
jest.mock('axios');
jest.mock('jsonld');

describe('verifyCredentials', () => {
    const mockCredential = {
        proof: {
            jws: 'mockJws',
            "proofPurpose": "assertionMethod",
            "type": "RsaSignature2018",
            verificationMethod: 'mockVerificationMethod',
        },
        "type": ["VerifiableCredential", "MOSIPVerifiableCredential"]
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should verify credentials successfully', async () => {

        jws.decode = jest.fn();
        jws.decode.mockReturnValue({ header: { alg: 'RS256' }, signature: 'mock-signature' });

        crypto.verify = jest.fn();
        crypto.verify.mockReturnValue(true);

        crypto.createPublicKey = jest.fn();
        crypto.createPublicKey.mockReturnValue({});

        jsonld.expand = jest.fn();
        jsonld.expand.mockReturnValue([{}]);

        jsonld.canonize = jest.fn();
        jsonld.canonize.mockReturnValue(Buffer.from('canonical-data'));

        axios.get = jest.fn();
        axios.get.mockReturnValue({ 'data': { 'publicKeyPem': 'publicKeyPem' } });


        const result = await verifyCredentials(mockCredential);

        expect(result).toBe(true);
    });

    it('should throw an error if verification fails', async () => {
        const mockError = new Error('Verification failed');
        jws.decode.mockImplementation(() => { throw mockError; });

        await expect(verifyCredentials(mockCredential)).rejects.toThrow(mockError);
    });

});










