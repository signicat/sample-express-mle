const fs = require('fs');
const jose = require('jose');

(async function() {
    const jwe = '<Paste JWE token here>';

    // Retrieve your private key, which will be used to decrypt the JWE token
    const pk = await getDecryptionKey();

    // Decrypt the token, which again contains a signed token (JWS)
    const { plaintext } = await jose.compactDecrypt(jwe, pk);
    const jws = new TextDecoder().decode(plaintext);
    
    // Retrieve the key set used to validate the JWS signature 
    const validationKeys = getValidationKeys();

    // Decode and validate the JWS, which returns the actual JSON payload
    const { payload } = await jose.jwtVerify(jws, validationKeys);

    console.log(payload);

}());

async function getDecryptionKey() {
    const json = fs.readFileSync('/path/to/key.json', 'utf-8');
    const jwk = JSON.parse(json);
    return jose.importJWK(jwk);
}

function getValidationKeys() {
    // This sample uses the JWKS endpoint for the REST API flow.
    // If you are using OpenID Connect, use the following endpoint: https://login.signicat.io/.well-known/openid-configuration/jwks
    const jwksEndpoint = 'https://api.signicat.io/identification/v2/jwks';
    
    return jose.createRemoteJWKSet(new URL(jwksEndpoint));
}