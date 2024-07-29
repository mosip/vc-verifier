import { jest } from '@jest/globals'
import { URDNA2015Canonicalizer } from '../../src/utils/URDNA2015Canonicalizer';
import jsonld from 'jsonld';
import crypto from 'crypto';

jest.mock('jsonld');

describe('URDNA2015Canonicalizer', () => {
  it('should return a canonicalized buffer of given data', async () => {
    const jsonldObject = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1"
      ],
      "proof": {
        "type": "RsaSignature2018",
        "jws": "mock-signature"
      },
      "issuer": "https://api.qa-inji.mosip.net/.well-known/ida-controller.json"
    };
    
    const hashMock = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValueOnce(Buffer.from('mockedHashValue')),
    };
    const createHashMock = jest.spyOn(crypto, 'createHash').mockImplementationOnce(() => hashMock);
    
    jsonld.expand = jest.fn();
    jsonld.canonize = jest.fn();

    jsonld.expand.mockResolvedValueOnce({});
    jsonld.canonize.mockResolvedValueOnce(Buffer.from('normalized-data'));

    jsonld.expand.mockResolvedValueOnce({});
    jsonld.canonize.mockResolvedValueOnce(Buffer.from('normalized-proof-data'));

    const result = await URDNA2015Canonicalizer(jsonldObject);

    expect(jsonld.expand).toHaveBeenCalledTimes(2);
    expect(jsonld.canonize).toHaveBeenCalledTimes(2);

    expect(createHashMock).toHaveBeenCalledWith('sha256');
    expect(hashMock.digest).toHaveBeenCalledTimes(1);
    expect(hashMock.update).toHaveBeenCalledTimes(1);
    expect(result).toBeInstanceOf(Buffer);
  });
});