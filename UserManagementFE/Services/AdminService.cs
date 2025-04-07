using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Microsoft.JSInterop;
using UserManagementFE.Models;
using UserManagementFE.Utils;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Encodings.Web;


namespace UserManagementFE.Services
{
    public interface IAdminService
    {
        Task<PagedResponse<ProfileModel>> GetUsersAsync(int page, int pageSize, string searchString);
        Task<string> CreateUserAsync(ProfileModel user);
        Task<string> UpdateUserAsync(ProfileModel user);
        Task DeleteUserAsync(int userId);
    }

    public class AdminService : IAdminService
    {
        private readonly HttpClient _httpClient;
        private readonly IJSRuntime _js;
        private readonly ILogger<AdminService> _logger;
        private readonly IPublicKeyStore _publicKeyStore;
        private EncryptionService _encryptionService;
        private readonly AESKeyService _aesKeyService;

        public AdminService(HttpClient httpClient, IJSRuntime js, ILogger<AdminService> logger, IPublicKeyStore publicKeyStore, EncryptionService encryptionService, AESKeyService aesKeyService)
        {
            _httpClient = httpClient;
            _js = js;
            _logger = logger;
            _publicKeyStore = publicKeyStore;
            _encryptionService = encryptionService;
            _aesKeyService = aesKeyService;

        }

        public async Task<PagedResponse<ProfileModel>> GetUsersAsync(int page, int pageSize, string searchString)
        {
            EncryptionService.SetKeys();
            //await AddAuthorizationHeader();
            var response = await _httpClient.GetAsync($"/api/User?n={EncryptionService.publicKeyFE.n}&e={EncryptionService.publicKeyFE.e}");
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
            NewResponse<List<ProfileModel>> newResponse = JsonSerializer.Deserialize<NewResponse<List<ProfileModel>>>(decryptedData);
            List<ProfileModel> listUser = newResponse.Data;
            return new PagedResponse<ProfileModel> { Items = listUser, TotalCount =  listUser.Count};
  
        }

        public async Task<string> CreateUserAsync(ProfileModel user)
        {
            EncryptionService.SetKeys();
            User newUser = new User
            {
                Username = user.Username,
                Password = user.Password,
                HoTen = user.HoTen,
                NgaySinh = user.NgaySinh,
                GioiTinh = user.GioiTinh,
                SoCCCD = user.SoCCCD,
                Sdt = user.Sdt,
                Email = user.Email,
                DiaChiThuongTru = user.DiaChiThuongTru,
                DiaChiTamTru = user.DiaChiTamTru,
                NgheNghiep = user.NgheNghiep,
                HonNhan = user.HonNhan,
                BangLaiXe = user.BangLaiXe,
                SoTKNganHang = user.SoTKNganHang,
                Role = "User"
            };
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
            var userJson = JsonSerializer.Serialize(newUser, options);
            Console.WriteLine($"userJson: {userJson}");
            //var dataBytes = Encoding.UTF8.GetBytes(userJson);

            // Tạo request object với mã hóa RSA
            byte[] aesKey = _aesKeyService.GetAesKey();

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

        public async Task<string> UpdateUserAsync(ProfileModel user)
        {
            EncryptionService.SetKeys();
            UpdateForAdminModel userWithoutPassword = new UpdateForAdminModel
            {
                Id = user.Id,
                Username = user.Username,
                HoTen = user.HoTen,
                NgaySinh = user.NgaySinh,
                GioiTinh = user.GioiTinh,
                SoCCCD = user.SoCCCD,
                Sdt = user.Sdt,
                Email = user.Email,
                DiaChiThuongTru = user.DiaChiThuongTru,
                DiaChiTamTru = user.DiaChiTamTru,
                NgheNghiep = user.NgheNghiep,
                HonNhan = user.HonNhan,
                BangLaiXe = user.BangLaiXe,
                SoTKNganHang = user.SoTKNganHang
            };
            int userId = user.Id;
            Console.WriteLine($"userId: {userId}");

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
            var userJson = JsonSerializer.Serialize(userWithoutPassword, options);
            Console.WriteLine($"userJson: {userJson}");
            //var dataBytes = Encoding.UTF8.GetBytes(userJson);

            // Tạo request object với mã hóa RSA
            byte[] aesKey = _aesKeyService.GetAesKey();

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

        public async Task DeleteUserAsync(int userId)
        {
            EncryptionService.SetKeys();
            //await AddAuthorizationHeader();
            var response = await _httpClient.DeleteAsync($"api/User/{userId}?n={EncryptionService.publicKeyFE.n}&e={EncryptionService.publicKeyFE.e}");
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }

            var decryptedData = _encryptionService.DecryptResponseData(responseObject);
            Console.WriteLine($"message: {decryptedData}");
        }
    }

    public class PagedResponse<T>
    {
        public List<T> Items { get; set; } = new();
        public int TotalCount { get; set; }
    }
} 