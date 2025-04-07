using System.Net.Http.Json;
using System.Numerics;
using System.Text;
using System.Text.Json;
using UserManagementFE.Models;
using UserManagementFE.Utils;
using System;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Blazored.SessionStorage;

namespace UserManagementFE.Services
{
    public class AuthService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<AuthService> _logger;
        private readonly RSAKeyService _rsaKeyService;
        private readonly IPublicKeyStore _publicKeyStore;
        private readonly ISessionStorageService _sessionStorage;
        private EncryptionService _encryptionService;


        public AuthService(HttpClient httpClient, ILogger<AuthService> logger, IPublicKeyStore publicKeyStore, ISessionStorageService sessionStorage, EncryptionService encryptionService, AESKeyService aesKeyService)
        {
            _httpClient = httpClient;
            _logger = logger;
            _publicKeyStore = publicKeyStore;
            _sessionStorage = sessionStorage;
            _encryptionService = encryptionService;
        }

        public async Task SaveUserId(int userId)
        {
            await _sessionStorage.SetItemAsync("userId", userId);
        }



        public async Task<string> LoginAsync(LoginModel user)
        {
            EncryptionService.SetKeys();
            CustomAES aes = new CustomAES();
            // Lấy public key từ backend
            var publicKeyJson = await _publicKeyStore.GetPublicKeyAsync();
            var publicKeyBE = JsonSerializer.Deserialize<PublicKey>(publicKeyJson);
            if (publicKeyBE == null || string.IsNullOrEmpty(publicKeyBE.n) || string.IsNullOrEmpty(publicKeyBE.e))
            {
                throw new Exception("Không thể lấy public key từ server.");
            }
            Console.WriteLine("npublicKeyBE: " + publicKeyBE.n + " epublicKeyBE: " + publicKeyBE.e);
            //var publicKeyBE = new PublicKey
            //{
            //    n = EncryptionService.publicKeyFE.n,
            //    e = EncryptionService.publicKeyFE.e
            //};

            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            // Chuyển dữ liệu user thành JSON
            var userJson = JsonSerializer.Serialize(user, options);
            Console.WriteLine($"userJson: {userJson}");
            //var dataBytes = Encoding.UTF8.GetBytes(userJson);

            // Tạo request object với mã hóa RSA
            byte[] aesKey = aes.GenerateAesKey();

            var request = _encryptionService.CreateRSARequest(aesKey, userJson, publicKeyBE);
            Console.WriteLine("------------");
            Console.WriteLine($"DataEncryptedByAes: {request.DataEncryptedByAes}");
            Console.WriteLine($"AesKeyMasked: {request.AesKeyMasked}");
            Console.WriteLine($"MaskEncryptedByRsa: {request.MaskEncryptedByRsa}");
            Console.WriteLine($"ePublicKeyFE: {request.PublicKeyFE.e}, nPK: {request.PublicKeyFE.n}");


            // Gửi request đến server
            var response = await _httpClient.PostAsJsonAsync("api/User/login", request);
            response.EnsureSuccessStatusCode();

            //Response responseObject = new Response {
            //    DataEncryptedbyAes = request.DataEncryptedByAes,
            //    AesKeyMasked = request.AesKeyMasked,
            //    MaskEncryptedByRsa = request.MaskEncryptedByRsa,
            //};
            // Xử lý response
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }
            string decryptedData = _encryptionService.DecryptResponseData(responseObject);
            NewResponse<ProfileModel> newResponse = JsonSerializer.Deserialize<NewResponse<ProfileModel>>(decryptedData);
            Console.WriteLine($"new Response: {newResponse}");

            ProfileModel loginResponse = newResponse.Data;
            int userId = loginResponse.Id;
            await SaveUserId(userId);
            Console.WriteLine($"decryptedData: {decryptedData}");

            return loginResponse.Role;
        }

        public async Task<string> RegisterAsync(User user)
        {
            EncryptionService.SetKeys();
            CustomAES aes = new CustomAES();
            // Lấy public key từ backend
            var publicKeyJson = await _publicKeyStore.GetPublicKeyAsync();
            var publicKeyBE = JsonSerializer.Deserialize<PublicKey>(publicKeyJson);
            if (publicKeyBE == null || string.IsNullOrEmpty(publicKeyBE.n) || string.IsNullOrEmpty(publicKeyBE.e))
            {
                throw new Exception("Không thể lấy public key từ server.");
            }

            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            // Chuyển dữ liệu user thành JSON
            var userJson = JsonSerializer.Serialize(user, options);
            //var dataBytes = Encoding.UTF8.GetBytes(userJson);

            // Tạo request object với mã hóa RSA
            // Tạo request object với mã hóa RSA
            byte[] aesKey = aes.GenerateAesKey();

            var request = _encryptionService.CreateRSARequest(aesKey, userJson, publicKeyBE);
            _logger.LogInformation("------------");
            _logger.LogInformation($"DataEncryptedByAes: {request.DataEncryptedByAes}");
            _logger.LogInformation($"AesKeyMasked: {request.AesKeyMasked}");
            _logger.LogInformation($"MaskEncryptedByRsa: {request.MaskEncryptedByRsa}");
            _logger.LogInformation($"ePublicKeyFE: {request.PublicKeyFE.e}, nPK: {request.PublicKeyFE.n}");

            // Gửi request đến server
            var response = await _httpClient.PostAsJsonAsync("api/User/register", request);
            response.EnsureSuccessStatusCode();

            // Xử lý response
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }
            string decryptedData = _encryptionService.DecryptResponseData(responseObject);
            Console.WriteLine($"decryptedData: {decryptedData}");

            // Giải mã và trả về thông báo
            return decryptedData;
        }
    }
}