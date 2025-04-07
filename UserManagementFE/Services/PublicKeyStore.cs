using System.Net.Http;
using System.Threading.Tasks;

namespace UserManagementFE.Services
{
    public interface IPublicKeyStore
    {
        Task<string> GetPublicKeyAsync();
    }

    public class PublicKeyStore : IPublicKeyStore
    {
        private readonly HttpClient _httpClient;

        public PublicKeyStore(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<string> GetPublicKeyAsync()
        {
            return await _httpClient.GetStringAsync("api/User/public-key");
        }

    }
}
