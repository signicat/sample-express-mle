using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Jose;

namespace JweDecrypt
{
    class JweDecrypt
    {
        static async Task Main(string[] args)
        {
            var jwe = "<Paste JWE token here>";
      
            // Retrieve your private key, which will be used to decrypt the JWE token
            var decryptionKey = GetDecryptionKey();

            // Decrypt the token, which again contains a signed token (JWS)
            var decryptedToken = Jose.JWE.Decrypt(jwe, decryptionKey);
            var jws = decryptedToken.Plaintext;
            
            // Retrieve the key used to validate the JWS signature
            var validationKey = await GetValidationKey(jws);

            // Decode and validate the JWS, which returns the actual JSON payload
            var payload = Jose.JWT.Decode(jws, validationKey);

            Console.WriteLine(payload);
        }
        
        private static RSA GetDecryptionKey()
        {
            // Read JWK private key from file and convert to RSA object 
            var json = File.ReadAllText("/path/to/key.json");
            var jwk = JsonSerializer.Deserialize<Dictionary<string, string>>(json);

            var rsaParams = new RSAParameters()
            {
                Exponent = Base64Url.Decode(jwk["e"]),
                Modulus = Base64Url.Decode(jwk["n"]),
                D = Base64Url.Decode(jwk["d"]),
                DP = Base64Url.Decode(jwk["dp"]),
                DQ = Base64Url.Decode(jwk["dq"]),
                P = Base64Url.Decode(jwk["p"]),
                Q = Base64Url.Decode(jwk["q"]),
                InverseQ = Base64Url.Decode(jwk["qi"])
            };

            return RSA.Create(rsaParams);
        }

        private static async Task<RSA> GetValidationKey(string jws)
        {
            var httpClient = new HttpClient();
            
            // Extract `kid` parameter from the signed token to find the ID of the key used to secure the JWS
            var kid = Jose.JWT.Headers(jws)["kid"].ToString();

            // This sample uses the JWKS endpoint for the Authentication REST API.
            // The API gateway targets the production environment by default.
            // Requests that contain a valid access token will automatically be routed to the correct environment.
            // Alternatively you can add the following header to target the test environment: `X-Signicat-Environment: Test`
            // If you are using OpenID Connect, use the following endpoint: https://login.signicat.io/.well-known/openid-configuration/jwks
            var jwksEndpoint = "https://api.signicat.io/identification/v2/jwks";
            
            // Download public keys from JWKS endpoint
            var json  = await httpClient.GetStringAsync(jwksEndpoint);
            var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(json);
            
            // Find the key that matches the key ID from the JWS
            var jwk = jwks.Keys.First(jwk => jwk["kid"].Equals(kid));
            
            // Convert JWK to RSA object
            var rsaParams = new RSAParameters()
            {
                Exponent = Base64Url.Decode(jwk["e"]),
                Modulus = Base64Url.Decode(jwk["n"]),
            };

            return RSA.Create(rsaParams);
        }
    }

    class JsonWebKeySet
    {
        [JsonPropertyName("keys")]
        public IEnumerable<Dictionary<string, string>> Keys { get; set; }
    }
}
