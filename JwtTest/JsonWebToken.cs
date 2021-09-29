using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace JwtTest
{
    public class JsonWebToken
    {

        static JsonWebToken()
        {
        }

        public static string Encode(object payload, string key)
        {
            return Encode(payload, Encoding.UTF8.GetBytes(key));
        }

        public static byte[] Hash(byte[] key, byte[] value)
        {
            using var sha = new HMACSHA256(key);
            return sha.ComputeHash(value);
        }

        public static string Encode(object payload, byte[] keyBytes)
        {
            var segments = new List<string>();
            var header = new { alg = "RS256", typ = "JWT" };

            byte[] headerBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));

            segments.Add(Base64UrlEncode(headerBytes));
            segments.Add(Base64UrlEncode(payloadBytes));

            var stringToSign = string.Join(".", segments.ToArray());

            var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            byte[] signature = Hash(keyBytes, bytesToSign);
            segments.Add(Base64UrlEncode(signature));

            return string.Join(".", segments.ToArray());
        }

        public static string Decode(string token, string key)
        {
            return Decode(token, key, true);
        }

        public static string Decode(string token, string key, bool verify)
        {
            var parts = token.Split('.');
            var header = parts[0];
            var payload = parts[1];
            byte[] crypto = Base64UrlDecode(parts[2]);

            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            var payloadData = JsonDocument.Parse(payloadJson).RootElement;

            if (verify)
            {
                var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
                var keyBytes = Encoding.UTF8.GetBytes(key);

                var signature = Hash(keyBytes, bytesToSign);
                var decodedCrypto = Convert.ToBase64String(crypto);
                var decodedSignature = Convert.ToBase64String(signature);

                if (decodedCrypto != decodedSignature)
                {
                    throw new ApplicationException(string.Format("Invalid signature. Expected {0} got {1}", decodedCrypto, decodedSignature));
                }
            }

            return payloadData.ToString();
        }

        // from JWT spec
        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        // from JWT spec
        private static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
    }
}
