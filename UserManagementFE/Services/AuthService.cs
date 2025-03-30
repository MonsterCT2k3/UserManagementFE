using System.Net.Http.Json;
using System.Numerics;
using System.Text;
using System.Text.Json;
using UserManagementFE.Models;
using UserManagementFE.Utils;
using System;
using System.Security.Cryptography;
using System.Text.Encodings.Web;

namespace UserManagementFE.Services
{
    public class AuthService
    {

        private readonly HttpClient _httpClient;
        private readonly ILogger<AuthService> _logger;
        private readonly RSAKeyService _rsaKeyService;
        private readonly IPublicKeyStore _publicKeyStore;


        public AuthService(HttpClient httpClient, ILogger<AuthService> logger, RSAKeyService rsaKeyService, IPublicKeyStore publicKeyStore)
        {
            _httpClient = httpClient;
            _logger = logger;
            _rsaKeyService = rsaKeyService;
            _publicKeyStore = publicKeyStore;
        }

        public Request CreateRSARequest(byte[] dataBytes, PublicKey publicKeyBE)
        {
            // Tạo mask ngẫu nhiên
            const int blockSize = 8;
            int maskLength = (int)Math.Ceiling((double)dataBytes.Length / blockSize) * blockSize;
            byte[] mask = new byte[maskLength];
            Random.Shared.NextBytes(mask);
            Console.WriteLine($"Generated Mask: {Convert.ToBase64String(mask)}");

            // Mã hóa mask bằng CustomRSA
            var rsa = new CustomRSA();
            var (n, e) = (BigInteger.Parse(publicKeyBE.n), BigInteger.Parse(publicKeyBE.e));
            BigInteger[] encryptedMaskBigIntegers = rsa.Encrypt(mask, n, e);
            byte[] encryptedMaskBytes = new byte[encryptedMaskBigIntegers.Length * blockSize];
            for (int i = 0; i < encryptedMaskBigIntegers.Length; i++)
            {
                byte[] bytes = encryptedMaskBigIntegers[i].ToByteArray();
                Array.Copy(bytes, 0, encryptedMaskBytes, i * blockSize, Math.Min(bytes.Length, blockSize));
            }
            string encryptedMaskBase64 = Convert.ToBase64String(encryptedMaskBytes);
            Console.WriteLine($"Encrypted Mask: {encryptedMaskBase64}");

            // Mã hóa dữ liệu bằng mask (XOR)
            byte[] maskedData = new byte[dataBytes.Length];
            for (int i = 0; i < dataBytes.Length; i++)
            {
                maskedData[i] = (byte)(dataBytes[i] ^ mask[i]);
            }
            Console.WriteLine($"Masked Data: {Convert.ToBase64String(maskedData)}");

            // Chuyển đổi sang base64
            var maskedDataBase64 = Convert.ToBase64String(maskedData);
            var publicKeyFE = _rsaKeyService.GetPublicKey();

            Console.WriteLine("------------");
            Console.WriteLine($"Data: {maskedDataBase64}");
            Console.WriteLine($"Mask: {encryptedMaskBase64}");
            Console.WriteLine($"PublicKeyFE.n: {publicKeyFE.n}, PublicKeyFE.e: {publicKeyFE.e}");
            Console.WriteLine("---------------");

            // Tạo request object
            return new Request
            {
                Data = maskedDataBase64,
                Mask = encryptedMaskBase64,
                PublicKeyFE = new PublicKey
                {
                    n = publicKeyFE.n.ToString(),
                    e = publicKeyFE.e.ToString()
                }
            };
        }


        public async Task<string> LoginAsync(LoginModel user)
        {
            // Lấy public key từ backend
            //var publicKeyJson = await _publicKeyStore.GetPublicKeyAsync();
            //var publicKeyBE = JsonSerializer.Deserialize<PublicKey>(publicKeyJson);
            //Console.WriteLine($"N: {publicKeyBE.n}, E: {publicKeyBE.e}");
            var publicKeyBE = new PublicKey {
                n = "1819933460419586753",
                e = "65537"
            };
            if (publicKeyBE == null || string.IsNullOrEmpty(publicKeyBE.n) || string.IsNullOrEmpty(publicKeyBE.e))
            {
                Console.WriteLine("Không thể lấy public key từ server.");
                throw new Exception("Không thể lấy public key từ server.");
            }

            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping // Cho phép giữ nguyên Unicode
            };

            // Chuyển dữ liệu user thành JSON
            var userJson = JsonSerializer.Serialize(user, options);
            var dataBytes = Encoding.UTF8.GetBytes(userJson);

            // Tạo request object
            var request = CreateRSARequest(dataBytes, publicKeyBE);
            _logger.LogInformation("------------");
            _logger.LogInformation($"Data: {request.Data}");
            _logger.LogInformation($"Mask: {request.Mask}");
            _logger.LogInformation($"PublicKeyFE: {request.PublicKeyFE}");

            string decodeResponse = DecryptResponseData(new Response { Data = request.Data, Mask = request.Mask});
            Console.WriteLine($"Decoded Response: {decodeResponse}");

            // Gửi yêu cầu POST
            var response = await _httpClient.PostAsJsonAsync("api/auth/login", request);
            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();

            // Xử lý phản hồi từ server
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }

            // Giải mã dữ liệu
            var decryptedData = DecryptResponseData(responseObject);
            return decryptedData;
        }

        public async Task<string> RegisterAsync(User user)
        {
            // Lấy public key từ backend
            //var publicKeyJson = await _publicKeyStore.GetPublicKeyAsync();
            //var publicKeyBE = JsonSerializer.Deserialize<PublicKey>(publicKeyJson);
            var publicKeyBE = new PublicKey
            {
                n = "1819933460419586753",
                e = "65537"
            };
            if (publicKeyBE == null || string.IsNullOrEmpty(publicKeyBE.n) || string.IsNullOrEmpty(publicKeyBE.e))
            {
                throw new Exception("Không thể lấy public key từ server.");
            }

            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping // Cho phép giữ nguyên Unicode
            };

            // Chuyển dữ liệu user thành JSON
            var userJson = JsonSerializer.Serialize(user, options);
            var dataBytes = Encoding.UTF8.GetBytes(userJson);

            // Tạo request object
            var request = CreateRSARequest(dataBytes, publicKeyBE);
            _logger.LogInformation("------------");
            _logger.LogInformation($"Data: {request.Data}");
            _logger.LogInformation($"Mask: {request.Mask}");
            _logger.LogInformation($"PublicKeyFE: {request.PublicKeyFE}");
            //string decodeResponse = DecryptResponseData(new Response { Data = request.Data, Mask = request.Mask });
            string decodeResponse = DecryptResponseData(new Response { Data = "xROoO6TjsJ8Wjk2XW4h6xdOcJwTx4njEY3hLm3EySpVBkZnbcGBBltxMRf5ko6hootR87mdzPGB/TUtXWpLIQLllD8dA4eHZr/o1xmv6gX4V/ODRl20KBqZGczhrFDFlvtl8q+V6gP0uLTDcWduAnGez3jMVBq/TT/RhfmKiIX+JG33t+8/8L798/zHmlW+14NoRBh6JuhDPHbTT4xE6MckNyVgONEAlqOXqmFgd0i3Ne7PZRV3QFU4gmZhl7wcTayREbYVarj7k6ja95y7fohxVBBxb+LZb7fItZxG0G/nGzD3QEciT3oW2DkABOfcQX+KRP9Qs8kYtgF3wyIiZf5t1fAegQ6eu/d9eW9BjqHbpFt7nBu+bq5hh7pL87Wd/wTOgAmB/lGjeJYnCfBtwF69c+qHgK3YQxPWgQ2bft57avgBwfn1HF22s4XXPdoBZRTZKu3QDTjplVSe1SAzs4CtrFYeoA+BrCWPRml6G/vsYGDlKiyTNCelmS7hJk9280Llh+6bIkBPkJotjVruMXiCanStk8mliwn2zS87pRddf18ov2u7QHzJNEBwxQs0z66/feQBxe84rbicjlwfh01ujIn5VbN0HqmWkkKpKaIOSW24x5h2Xir6967FAl6TcQxScelsn/h7AuIc+v9ppM3M2Cc7WLoUU4Q791LqB9AaDKlcPUYnohJBJaSuKWeQZdIHIDoEJelRqtHDwYEj8kMSLW9z+Rnq6PoBPFlqmfi3Q1GHE9BkYFfa8pWoaqXNuSIURZ7Ti/hYLd1gq0EUTrBdVz8oP8YvUAIWI+LOxRRUkqDRDrlhtI12YqVuoi2T9Pf4e/PqdaTxyspgal6Lekh/zKbtZuHY1/1ZqM7EBJI1F4fPfKJrpr1iuwZv1rNNDc6Wf5kYeGjFfASOccbXTEFdZHuqp9K7eJht1k5HBj3mBVQqgaNOWkK5Ocnr3JEiXU0W98sRjRDfrjjnQXr8rJ1rQUT/ru6pTRxm1iz+ghK7+ZahzHZ3aBWMH8Ar2DBcmaP93vetefLBvZnPq4eEcxxIVgK0WAyc+LmMiScOBuT6YDngFA0W2TYtp3be+6fpqmGLNJilI6C1B17o985hcV7euJAFUSZyguNOD4mI/J+kP+JSDYxcXn9dY2KRlrHTKnlehEGkOzJ/ocXwSjCmhlXqwR/S6uIU9F2oCS4FPvvUpbdcko+4PoW8nkMVGvWlPy9RAU4h7f530FCN6++c8V9RWYnK2+1vZ+NOYBA5381Ago0I5v+TT5MgQMUkJIIM6gd+41JSkZJogPic=", Mask = "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" });
            Console.WriteLine($"Decoded Response: {decodeResponse}");

            // Gửi yêu cầu POST
            var response = await _httpClient.PostAsJsonAsync("api/User/register", request);
            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();

            // Xử lý phản hồi từ server
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }

            // Giải mã dữ liệu
            var decryptedData = DecryptResponseData(responseObject);
            return decryptedData;
        }

        private string DecryptResponseData(Response response)
        {
            const int blockSize = 8;
            // Giải mã mask bằng khóa riêng tư của FE
            //var privateKey = _rsaKeyService.GetPrivateKey();
            //Console.WriteLine($"PrivateKey.n: {privateKey.n}, PrivateKey.d: {privateKey.d}");
            //var privateKey = (BigInteger.Parse("575638414164969557"), BigInteger.Parse("6016636590585053"));
            var rsa = new CustomRSA();
            byte[] maskedData = Convert.FromBase64String(response.Data);
            byte[] encryptedMaskBytes = Convert.FromBase64String(response.Mask);
            BigInteger[] encryptedMask = new BigInteger[maskedData.Length];
            for (int i = 0; i < maskedData.Length; i++)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(encryptedMaskBytes, i * blockSize, block, 0, blockSize);
                encryptedMask[i] = new BigInteger(block);
            }
            //byte[] decryptedMask = rsa.Decrypt(encryptedMask, privateKey.n, privateKey.d);
            byte[] decryptedMask = rsa.Decrypt(encryptedMask, BigInteger.Parse("575638414164969557"), BigInteger.Parse("6016636590585053"));

            // Giải mã dữ liệu bằng mask (XOR)
            byte[] originalData = new byte[maskedData.Length];
            for (int i = 0; i < maskedData.Length; i++)
            {
                originalData[i] = (byte)(maskedData[i] ^ decryptedMask[i]);
            }

            // Chuyển đổi dữ liệu gốc từ byte[] sang string
            return Encoding.UTF8.GetString(originalData);
        }
    }
}