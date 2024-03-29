using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace AppStoreConnector
{
    public class Connector
    {
        public static async ValueTask<bool> ConnectWithIndividualKey(string keyId, string privateKeyPath)
        {
            try
            {
                var credentials = GetCredentials(privateKeyPath);

                var header = new JwtHeader(credentials)
                {
                    { "kid", keyId }
                };

                var payload = new JwtPayload
                {
                    { "sub", "user" },
                    { "exp", DateTimeOffset.UtcNow.AddMinutes(20).ToUnixTimeSeconds() },
                    { "aud", "appstoreconnect-v1" }
                };

                return await Connect(header, payload);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public static async ValueTask<bool> ConnectWithTeamKey(string keyId, string issuerId, string privateKeyPath)
        {
            try
            {
                var credentials = GetCredentials(privateKeyPath);

                var header = new JwtHeader(credentials)
                {
                    { "kid", keyId }
                };

                var payload = new JwtPayload
                {
                    { "iss", issuerId },
                    { "exp", DateTimeOffset.UtcNow.AddMinutes(20).ToUnixTimeSeconds() },
                    { "aud", "appstoreconnect-v1" }
                };

                return await Connect(header, payload);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        private static async ValueTask<bool> Connect(JwtHeader header, JwtPayload payload)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken(header, payload);
            var jwtToken = tokenHandler.WriteToken(token);

            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
                var url = "https://api.appstoreconnect.apple.com/v1/apps";
                var response = await httpClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"response: {content}");
                return response.IsSuccessStatusCode;
            }
        }

        private static SigningCredentials GetCredentials(string privateKeyPath)
        {
            var privateKey = File.ReadAllText(privateKeyPath);
            var ecdsa = LoadPrivateKey(privateKey);
            var securityKey = new ECDsaSecurityKey(ecdsa);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);
            return credentials;
        }

        private static ECDsa LoadPrivateKey(string privateKey)
        {
            using (var reader = new StringReader(privateKey))
            {
                var pemReader = new PemReader(reader);

                if (!(pemReader.ReadObject() is ECPrivateKeyParameters keyPair))
                    throw new Exception("Could not read EC private key from PEM.");

                var domainParameters = keyPair.Parameters;
                var ecPoint = domainParameters.G.Multiply(keyPair.D).Normalize();
                var x = ecPoint.AffineXCoord.GetEncoded();
                var y = ecPoint.AffineYCoord.GetEncoded();
                var d = keyPair.D.ToByteArrayUnsigned();

                var ecParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = d,
                    Q = new ECPoint
                    {
                        X = x,
                        Y = y
                    }
                };

                var ecdsa = ECDsa.Create();
                ecdsa.ImportParameters(ecParameters);
                return ecdsa;
            }
        }
    }
}
