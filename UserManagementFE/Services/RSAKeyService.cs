using System;
using System.Numerics;
using UserManagementFE.Utils;

namespace UserManagementFE.Services
{
    public class RSAKeyService
    {
        private  CustomRSA _rsa;
        private (BigInteger n, BigInteger e) _publicKey;
        private (BigInteger n, BigInteger d) _privateKey;

        public RSAKeyService()
        {
            GenerateNewKeys();
        }

        public (BigInteger n, BigInteger e) GetPublicKey()
        {
            return _publicKey;
        }

        public (BigInteger n, BigInteger d) GetPrivateKey()
        {
            return _privateKey;
        }

        public void GenerateNewKeys()
        {
            _rsa = new CustomRSA();
            _publicKey = _rsa.GetPublicKey();
            _privateKey = _rsa.GetPrivateKey();
        }
    }
}
