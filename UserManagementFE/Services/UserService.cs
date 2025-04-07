using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.JSInterop;
using UserManagementFE.Models;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text;
using System.Numerics;
using UserManagementFE.Utils;
using Blazored.SessionStorage;

namespace UserManagementFE.Services
{
    public class UserService
    {
        private readonly HttpClient _httpClient;
        private readonly IJSRuntime _js;
        private readonly ILogger<UserService> _logger;
        private readonly IPublicKeyStore _publicKeyStore;
        private readonly ISessionStorageService _sessionStorage;
        private EncryptionService _encryptionService;

        public UserService(HttpClient httpClient, IJSRuntime js, ILogger<UserService> logger, IPublicKeyStore publicKeyStore, ISessionStorageService sessionStorage, EncryptionService encryptionService)
        {
            _httpClient = httpClient;
            _js = js;
            _logger = logger;
            _publicKeyStore = publicKeyStore;
            _sessionStorage = sessionStorage;
            _encryptionService = encryptionService;
        }

        

		public async Task<ProfileModel?> GetProfileAsync()
		{
            EncryptionService.SetKeys();
            //await AddAuthorizationHeader();
			int userId = await _sessionStorage.GetItemAsync<int>("userId");
			Console.WriteLine($"userId: {userId}");
			var response = await _httpClient.GetAsync($"api/User/{userId}?n={EncryptionService.publicKeyFE.n}&e={EncryptionService.publicKeyFE.e}");
			response.EnsureSuccessStatusCode();

			var responseContent = await response.Content.ReadAsStringAsync();
			var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
			if (responseObject == null)
			{
				throw new Exception("Phản hồi từ server không hợp lệ.");
			}

			var decryptedData = _encryptionService.DecryptResponseData(responseObject);
			Console.WriteLine($"data profile: {decryptedData}");

			NewResponse<ProfileModel> newResponse = JsonSerializer.Deserialize<NewResponse<ProfileModel>>(decryptedData);
            ProfileModel loginResponse = newResponse.Data;
            return loginResponse;
		}


		public async Task<List<ProfileModel>> GetOtherUsersAsync()
        {
            EncryptionService.SetKeys();
            //await AddAuthorizationHeader();
            int userId =  await _sessionStorage.GetItemAsync<int>("userId");
            Console.WriteLine($"userId: {userId}");
            var response = await _httpClient.GetAsync($"api/User/except/{userId}?n={EncryptionService.publicKeyFE.n}&e={EncryptionService.publicKeyFE.e}");
            response.EnsureSuccessStatusCode();
            
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }

            var decryptedData = _encryptionService.DecryptResponseData(responseObject);
            Console.WriteLine($"data profile: {decryptedData}");
            NewResponse<List<ProfileModel>> newResponse = JsonSerializer.Deserialize< NewResponse<List<ProfileModel>>>(decryptedData);
            Console.WriteLine($"new Response: {newResponse}");
            var otherUsers = newResponse.Data;
            return otherUsers;
        }

        public async Task<string> EditProfileAsync(ProfileModel user)
        {
            EncryptionService.SetKeys();
            int userId = await _sessionStorage.GetItemAsync<int>("userId");
            Console.WriteLine($"userId: {userId}");
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

            // Tạo request object với mã hóa RSA
            byte[] aesKey = aes.GenerateAesKey();

            var request = _encryptionService.CreateRSARequest(aesKey, userJson, publicKeyBE);
            _logger.LogInformation("------------");
            _logger.LogInformation($"DataEncryptedByAes: {request.DataEncryptedByAes}");
            _logger.LogInformation($"AesKeyMasked: {request.AesKeyMasked}");
            _logger.LogInformation($"MaskEncryptedByRsa: {request.MaskEncryptedByRsa}");
            _logger.LogInformation($"ePublicKeyFE: {request.PublicKeyFE.e}, nPK: {request.PublicKeyFE.n}");

            // Gửi request đến server
            var response = await _httpClient.PutAsJsonAsync($"api/User/{userId}", request);
            response.EnsureSuccessStatusCode();

            // Xử lý response
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }
            var decryptedData = _encryptionService.DecryptResponseData(responseObject);
            Console.WriteLine($"new data: {decryptedData}");
            return decryptedData;
        }

        public async Task<string> ChangePasswordAsync(ChangePasswordRequest changePassWordrequest)
        {
            EncryptionService.SetKeys();
            int userId = await _sessionStorage.GetItemAsync<int>("userId");
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
            Console.WriteLine("-------------");
            // Chuyển dữ liệu request thành JSON
            var requestJson = JsonSerializer.Serialize(changePassWordrequest, options);
            //var dataBytes = Encoding.UTF8.GetBytes(requestJson);
            Console.WriteLine($"requestJson: {requestJson}");
            // Tạo request object với mã hóa RSA
            byte[] aesKey = aes.GenerateAesKey();
            Console.WriteLine($"aesKey: {Convert.ToBase64String(aesKey)}");

            var request = _encryptionService.CreateRSARequest(aesKey, requestJson, publicKeyBE);
            Console.WriteLine("------------");
            Console.WriteLine($"DataEncryptedByAes: {request.DataEncryptedByAes}");
            Console.WriteLine($"AesKeyMasked: {request.AesKeyMasked}");
            Console.WriteLine($"MaskEncryptedByRsa: {request.MaskEncryptedByRsa}");
            Console.WriteLine($"ePublicKeyFE: {request.PublicKeyFE.e}, nPK: {request.PublicKeyFE.n}");

            // Gửi request đến server
            var response = await _httpClient.PutAsJsonAsync($"api/User/changePassword/{userId}", request);
            response.EnsureSuccessStatusCode();

            // Xử lý response
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }

            var decryptedData = _encryptionService.DecryptResponseData(responseObject);
            Console.WriteLine($"new data: {decryptedData}");
            return decryptedData;
        }
    }

    public class ChangePasswordRequest
    {
        public string OldPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
}