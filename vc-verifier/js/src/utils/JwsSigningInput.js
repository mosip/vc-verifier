export const getJwsSigningInput = (header, signingInput) => {
    const buffer = Buffer.from(JSON.stringify(header), 'utf8');
    const base64url = buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const encodedHeader = Buffer.from(base64url, 'utf8');
    const jwsSigningInput = Buffer.alloc(encodedHeader.length + 1 + signingInput.length);

    Buffer.concat([encodedHeader, Buffer.from('.', 'utf8'), signingInput]).copy(jwsSigningInput, 0);

    return jwsSigningInput;
}