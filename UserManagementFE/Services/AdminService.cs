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
        Request CreateRSARequest(byte[] dataBytes, PublicKey publicKeyBE);
    }

    public class AdminService : IAdminService
    {
        private readonly HttpClient _httpClient;
        private readonly IJSRuntime _js;
        private readonly ILogger<AdminService> _logger;
        private readonly RSAKeyService _rsaKeyService;
        private readonly IPublicKeyStore _publicKeyStore;

        public AdminService(HttpClient httpClient, IJSRuntime js, ILogger<AdminService> logger, RSAKeyService rsaKeyService, IPublicKeyStore publicKeyStore)
        {
            _httpClient = httpClient;
            _js = js;
            _logger = logger;
            _rsaKeyService = rsaKeyService;
            _publicKeyStore = publicKeyStore;
        }

        public Request CreateRSARequest(byte[] dataBytes, PublicKey publicKeyBE)
        {
            // Tạo mask ngẫu nhiên với độ dài bằng với dữ liệu
            byte[] mask = new byte[dataBytes.Length];
            Random.Shared.NextBytes(mask);

            // Mã hóa mask bằng CustomRSA
            var rsa = new CustomRSA();
            var (n, e) = (BigInteger.Parse(publicKeyBE.n), BigInteger.Parse(publicKeyBE.e));
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
            byte[] encryptedMaskBytes = Convert.FromBase64String(response.Mask);

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

            private async Task AddAuthorizationHeader()
        {
            var token = await _js.InvokeAsync<string>("localStorage.getItem", "authToken");
            if (!string.IsNullOrEmpty(token))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        public async Task<PagedResponse<ProfileModel>> GetUsersAsync(int page, int pageSize, string searchString)
        {
            //await AddAuthorizationHeader();
            var (n, e) = _rsaKeyService.GetPublicKey();
            var response = await _httpClient.GetAsync($"/api/User?n={n}&e={e}");
            response.EnsureSuccessStatusCode();
            // Xử lý response
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }
            string decryptedData = DecryptResponseData(responseObject);
            Console.WriteLine($"decryptedData: {decryptedData}");
            List<ProfileModel> listUser = JsonSerializer.Deserialize<List<ProfileModel>>(decryptedData);
            return new PagedResponse<ProfileModel> { Items = listUser, TotalCount =  listUser.Count};
  
        }

        public async Task<string> CreateUserAsync(ProfileModel user)
        {
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
            var dataBytes = Encoding.UTF8.GetBytes(userJson);

            // Tạo request object với mã hóa RSA
            var request = CreateRSARequest(dataBytes, publicKeyBE);
            _logger.LogInformation("------------");
            _logger.LogInformation($"Data: {request.Data}");
            _logger.LogInformation($"Mask: {request.Mask}");
            _logger.LogInformation($"PublicKeyFE: {request.PublicKeyFE}");

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
            string decryptedData = DecryptResponseData(responseObject);
            Console.WriteLine($"decryptedData: {decryptedData}");

            // Giải mã và trả về thông báo
            return decryptedData;
        }

        public async Task<string> UpdateUserAsync(ProfileModel user)
        {
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

        public async Task DeleteUserAsync(int userId)
        {

            //await AddAuthorizationHeader();
            var (n, e) = _rsaKeyService.GetPublicKey();
            Console.WriteLine($"userId: {userId}");
            Console.WriteLine($"n: {n}, e: {e}");
            var response = await _httpClient.DeleteAsync($"api/User/{userId}?n={n}&e={e}");
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObject = JsonSerializer.Deserialize<Response>(responseContent);
            if (responseObject == null)
            {
                throw new Exception("Phản hồi từ server không hợp lệ.");
            }

            var decryptedData = DecryptResponseData(responseObject);
            Console.WriteLine($"message: {decryptedData}");
        }
    }

    public class PagedResponse<T>
    {
        public List<T> Items { get; set; } = new();
        public int TotalCount { get; set; }
    }
} 