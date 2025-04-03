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
        private readonly RSAKeyService _rsaKeyService;
        private readonly IPublicKeyStore _publicKeyStore;
        private readonly ISessionStorageService _sessionStorage;

        public UserService(HttpClient httpClient, IJSRuntime js, ILogger<UserService> logger, RSAKeyService rsaKeyService, IPublicKeyStore publicKeyStore, ISessionStorageService sessionStorage)
        {
            _httpClient = httpClient;
            _js = js;
            _logger = logger;
            _rsaKeyService = rsaKeyService;
            _publicKeyStore = publicKeyStore;
            _sessionStorage = sessionStorage;
        }

        private async Task AddAuthorizationHeader()
        {
            var token = await _js.InvokeAsync<string>("localStorage.getItem", "authToken");
            if (!string.IsNullOrEmpty(token))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        private Request CreateRSARequest(byte[] dataBytes, PublicKey publicKeyBE)
        {
            // Tạo mask ngẫu nhiên với độ dài bằng với dữ liệu
            byte[] mask = new byte[dataBytes.Length];
            Random.Shared.NextBytes(mask);

            // Mã hóa mask bằng CustomRSA
            var rsa = new CustomRSA();
            var (n, e) = (BigInteger.Parse(publicKeyBE.n), BigInteger.Parse(publicKeyBE.e));
            //BigInteger[] encryptedMaskBigIntegers = rsa.Encrypt(mask, 1047506601960900899, 65537);
            BigInteger[] encryptedMaskBigIntegers = rsa.Encrypt(mask, n, e);

            // Chuyển đổi BigInteger[] thành byte[]
            const int blockSize = 8;
            byte[] encryptedMaskBytes = new byte[encryptedMaskBigIntegers.Length * blockSize];
            for (int i = 0; i < encryptedMaskBigIntegers.Length; i++)
            {
                byte[] bytes = encryptedMaskBigIntegers[i].ToByteArray();
                if (bytes.Length > blockSize)
                {
                    Array.Copy(bytes, 0, encryptedMaskBytes, i * blockSize, blockSize);
                }
                else
                {
                    Array.Copy(bytes, 0, encryptedMaskBytes, i * blockSize, bytes.Length);
                }
            }

            // Mã hóa dữ liệu bằng mask (XOR)
            byte[] maskedData = new byte[dataBytes.Length];
            for (int i = 0; i < dataBytes.Length; i++)
            {
                maskedData[i] = (byte)(dataBytes[i] ^ mask[i]);
            }

            // Chuyển đổi sang base64
            var maskedDataBase64 = Convert.ToBase64String(maskedData);
            var encryptedMaskBase64 = Convert.ToBase64String(encryptedMaskBytes);
            var publicKeyFE = _rsaKeyService.GetPublicKey();
            var privateKey = _rsaKeyService.GetPrivateKey();
            Console.WriteLine($"n: {publicKeyFE.n}, e: {publicKeyFE.e}");
            Console.WriteLine("------------");
            Console.WriteLine($"n: {privateKey.n}, d: {privateKey.d}");

            //        n: 1047506601960900899, e: 65537
            //blazor.webassembly.js:1------------
            //blazor.webassembly.js:1 n: 1047506601960900899, d: 25046047909419353

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

        private string DecryptResponseData(Response response)
        {
            const int blockSize = 8;
            var rsa = new CustomRSA();

            // Chuyển đổi base64 thành byte[]
            byte[] maskedData = Convert.FromBase64String(response.Data);
            //byte[] maskedData = Convert.FromBase64String("RPejLCVR6F+pf3y19eDOVwDWSaepTCv05Gi/wzOHJXnJXhTmF8uGBSlkSi5ui74EpwmHuGegwugZswDRDRuOtla7WssuiOtCS6/bPCpSDGiKJAg2hSJ4oY0XHyryYcT0Vh5fr/FsmI2ieK9tN5204osI1kQd4WXHyIcCMsWoAFGD10DQjFDifipsJuJTitDp6b1MAgQldEuHNnMchPxo+Z8b/GA5klZXM0FOrKuNIeNZRt4ObeK/Wvn2vDMktWmER3oG6Z1dPk8Pu6DrFV3fhQYgKiDYGxV8X/VSgA2YhFPfLD17LENOZW4K/lSLv3R3RsapnoV26hGIyi5bgSlznbm5S75UdT0A+Q6rW3XMrbKIyrDthCzKGc6+rR59r1s=");
            byte[] encryptedMaskBytes = Convert.FromBase64String(response.Mask);
            //byte[] encryptedMaskBytes = Convert.FromBase64String("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\r\n");

            // Chuyển đổi byte[] thành BigInteger[]
            int numBlocks = encryptedMaskBytes.Length / blockSize;
            BigInteger[] encryptedMask = new BigInteger[numBlocks];
            for (int i = 0; i < numBlocks; i++)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(encryptedMaskBytes, i * blockSize, block, 0, blockSize);
                encryptedMask[i] = new BigInteger(block);
            }
            var privateKey = _rsaKeyService.GetPrivateKey();
            Console.WriteLine("------------");
            Console.WriteLine($"npk: {privateKey.n}, dpk: {privateKey.d}");

            // Giải mã mask
            byte[] decryptedMask = rsa.Decrypt(encryptedMask, privateKey.n, privateKey.d);
            //byte[] decryptedMask = rsa.Decrypt(encryptedMask, 1047506601960900899, 25046047909419353);

            // Đảm bảo độ dài mask bằng với dữ liệu
            if (decryptedMask.Length > maskedData.Length)
            {
                Array.Resize(ref decryptedMask, maskedData.Length);
            }

            // Giải mã dữ liệu bằng mask (XOR)
            byte[] originalData = new byte[maskedData.Length];
            for (int i = 0; i < maskedData.Length; i++)
            {
                originalData[i] = (byte)(maskedData[i] ^ decryptedMask[i]);
            }
            Console.WriteLine(Encoding.UTF8.GetString(originalData));

            // Chuyển đổi dữ liệu gốc từ byte[] sang string
            return Encoding.UTF8.GetString(originalData);
        }

		public async Task<ProfileModel?> GetProfileAsync()
		{
			//await AddAuthorizationHeader();
			var (n, e) = _rsaKeyService.GetPublicKey();
			int userId = await _sessionStorage.GetItemAsync<int>("userId");
			Console.WriteLine($"userId: {userId}");
			Console.WriteLine($"n: {n}, e: {e}");
			var response = await _httpClient.GetAsync($"api/User/{userId}?n={n}&e={e}");
			response.EnsureSuccessStatusCode();

			var responseContent = await response.Content.ReadAsStringAsync();
			var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
			if (responseObject == null)
			{
				throw new Exception("Phản hồi từ server không hợp lệ.");
			}

			var decryptedData = DecryptResponseData(responseObject);
			Console.WriteLine($"data profile: {decryptedData}");
			ProfileModel loginResponse = JsonSerializer.Deserialize<ProfileModel>(decryptedData);
			return loginResponse;
		}


		public async Task<List<ProfileModel>> GetOtherUsersAsync()
        {
            //await AddAuthorizationHeader();
            var (n, e) =  _rsaKeyService.GetPublicKey();
            int userId =  await _sessionStorage.GetItemAsync<int>("userId");
            Console.WriteLine($"userId: {userId}");
            Console.WriteLine($"n: {n}, e: {e}");
            var response = await _httpClient.GetAsync($"api/User/except/{userId}?n={n}&e={e}");
            response.EnsureSuccessStatusCode();
            
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }

            var decryptedData = DecryptResponseData(responseObject);
            Console.WriteLine($"data profile: {decryptedData}");
			List<ProfileModel> otherUsers = JsonSerializer.Deserialize<List<ProfileModel>>(decryptedData);
            return otherUsers;
        }

        public async Task<string> EditProfileAsync(ProfileModel user)
        {
            //var (n, e) = _rsaKeyService.GetPublicKey();
            int userId = await _sessionStorage.GetItemAsync<int>("userId");
            Console.WriteLine($"userId: {userId}");
            //Console.WriteLine($"n: {n}, e: {e}");
            //await AddAuthorizationHeader();

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
            var dataBytes = Encoding.UTF8.GetBytes(userJson);

            // Tạo request object với mã hóa RSA
            var request = CreateRSARequest(dataBytes, publicKeyBE);

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
            var decryptedData = DecryptResponseData(responseObject);
            Console.WriteLine($"new data: {decryptedData}");
            return decryptedData;
        }

        public async Task<string> ChangePasswordAsync(ChangePasswordRequest request)
        {
            int userId = await _sessionStorage.GetItemAsync<int>("userId");

            //await AddAuthorizationHeader();

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

            // Chuyển dữ liệu request thành JSON
            var requestJson = JsonSerializer.Serialize(request, options);
            var dataBytes = Encoding.UTF8.GetBytes(requestJson);

            // Tạo request object với mã hóa RSA
            var encryptedRequest = CreateRSARequest(dataBytes, publicKeyBE);

            // Gửi request đến server
            var response = await _httpClient.PutAsJsonAsync($"api/User/changePassword/{userId}", encryptedRequest);
            response.EnsureSuccessStatusCode();

            // Xử lý response
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }

            var decryptedData = DecryptResponseData(responseObject);
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