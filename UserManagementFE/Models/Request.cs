namespace UserManagementFE.Models
{
    public class Request
    {
        public string DataEncryptedByAes { get; set; } = string.Empty;
        public string AesKeyMasked { get; set; } = string.Empty;
        public string MaskEncryptedByRsa { get; set; } = string.Empty;
        public PublicKey PublicKeyFE { get; set; } = new PublicKey();
    }
}
