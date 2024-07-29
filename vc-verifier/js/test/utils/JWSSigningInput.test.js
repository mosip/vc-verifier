import { getJwsSigningInput } from '../../src/utils/JwsSigningInput';

describe('getJwsSigningInput', () => {
  it('should return a JWS signing input', () => {
    const expectedResult = Buffer.from([101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 74, 57, 46, 115, 105, 103, 110, 105, 110, 103, 45, 105, 110, 112, 117, 116, 45, 100, 97, 116, 97]);

    const header = { alg: 'RS256' };
    const signingInput = Buffer.from('signing-input-data');
    const result = getJwsSigningInput(header, signingInput);

    expect(result).toBeInstanceOf(Buffer);
    expect(result).toStrictEqual(expectedResult);
  });
});

