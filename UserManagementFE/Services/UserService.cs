using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.JSInterop;
using UserManagementFE.Models;

namespace UserManagementFE.Services
{
    public class UserService
    {
        private readonly HttpClient _httpClient;
        private readonly IJSRuntime _js;

        public UserService(HttpClient httpClient, IJSRuntime js)
        {
            _httpClient = httpClient;
            _js = js;
        }

        private async Task AddAuthorizationHeader()
        {
            var token = await _js.InvokeAsync<string>("localStorage.getItem", "authToken");
            if (!string.IsNullOrEmpty(token))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        public async Task<User?> GetProfileAsync()
        {
            await AddAuthorizationHeader();
            var response = await _httpClient.GetAsync("api/user/profile");
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<User>();
        }

        public async Task<string> EditProfileAsync(User user)
        {
            await AddAuthorizationHeader();
            var response = await _httpClient.PutAsJsonAsync("api/user/edit-profile", user);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }

        public async Task<string> ChangePasswordAsync(ChangePasswordRequest request)
        {
            await AddAuthorizationHeader();
            var response = await _httpClient.PutAsJsonAsync("api/user/change-password", request);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
    }

    public class ChangePasswordRequest
    {
        public string OldPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
}