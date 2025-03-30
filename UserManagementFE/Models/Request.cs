namespace UserManagementFE.Models
{
    public class Request
    {
        public string Data { get; set; } = string.Empty;
        public string Mask { get; set; } = string.Empty;
        public PublicKey PublicKeyFE { get; set; } = new PublicKey();
    }
}
