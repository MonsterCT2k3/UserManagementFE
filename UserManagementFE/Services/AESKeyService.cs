using System.Security.Cryptography;
using UserManagementFE.Utils;

namespace UserManagementFE.Services
{
    public class AESKeyService
    {
        private CustomAES _aes;
        private byte[] _keyAes;

        public AESKeyService()
        {
            GenerateNewKeys();
        }
        public byte[] GetAesKey()
        {
            return _keyAes;
        }
        public void GenerateNewKeys()
        {
            _aes = new CustomAES();
            _keyAes = _aes.GenerateAesKey();
        }
    }
}
