using System.Net.Http;
using System.Threading.Tasks;

namespace UserManagementFE.Services
{
    public interface IPublicKeyStore
    {
        Task<string> GetPublicKeyAsync();
        void SetPublicKey(string publicKey);
    }

    public class PublicKeyStore : IPublicKeyStore
    {
        private string _publicKey;
        private readonly HttpClient _httpClient;

        public PublicKeyStore(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<string> GetPublicKeyAsync()
        {
            if (string.IsNullOrEmpty(_publicKey))
            {
                _publicKey = await _httpClient.GetStringAsync("api/User/public-key");
            }
            return _publicKey;
        }

        public void SetPublicKey(string publicKey)
        {
            _publicKey = publicKey;
        }
    }
}
