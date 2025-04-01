using System.Text.Json.Serialization;

namespace UserManagementFE.Models
{
    public class LoginResponse
    {
        [JsonPropertyName("Message")]
        public string Message { get; set; } = string.Empty;

        [JsonPropertyName("User")]
        public ProfileModel User { get; set; } = new();
    }
}