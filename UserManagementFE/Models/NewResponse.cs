using System.Text.Json.Serialization;

namespace UserManagementFE.Models
{
    public class NewResponse<T>
    {
        [JsonPropertyName("Message")]
        public string Message { get; set; }

        [JsonPropertyName("Data")]
        public T Data { get; set; }
    }

}
