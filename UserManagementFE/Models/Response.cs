namespace UserManagementFE.Models
{
    public class Response
    {
        public string DataEncryptedbyAes { get; set; } = string.Empty;
        public string AesKeyMasked { get; set; } = string.Empty;
        public string MaskEncryptedByRsa { get; set; } = string.Empty;
    }
}
