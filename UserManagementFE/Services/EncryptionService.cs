using System.Numerics;
using UserManagementFE.Models;
using UserManagementFE.Utils;

namespace UserManagementFE.Services
{
    public class EncryptionService
    {
        public static PublicKey publicKeyFE;
        public static PrivateKey privateKeyFE;

        public static void SetKeys()
        {
            RSAKeyService rsaKeyService = new RSAKeyService();
            publicKeyFE = new PublicKey
            {
                n = rsaKeyService.GetPublicKey().n.ToString(),
                e = rsaKeyService.GetPublicKey().e.ToString()
            };
            privateKeyFE = new PrivateKey
            {
                n = rsaKeyService.GetPrivateKey().n.ToString(),
                d = rsaKeyService.GetPrivateKey().d.ToString()
            };

            Console.WriteLine($"Public Key: n = {publicKeyFE.n}, e = {publicKeyFE.e}");
            Console.WriteLine($"Private Key: n = {privateKeyFE.n}, d = {privateKeyFE.d}");
        }
        public Request CreateRSARequest(byte[] aesKeyByte, string data, PublicKey publicKeyBE)
        {
            // Tạo mask ngẫu nhiên với độ dài bằng với dữ liệu
            const int blockSize = 16;
            int maskLength = (int)Math.Ceiling((double)aesKeyByte.Length / blockSize) * blockSize;
            byte[] mask = new byte[maskLength];
            Random.Shared.NextBytes(mask);

            // Mã hóa mask bằng CustomRSA
            var rsa = new CustomRSA();
            var aes = new CustomAES();
            var (n, e) = (BigInteger.Parse(publicKeyBE.n), BigInteger.Parse(publicKeyBE.e));
            
            BigInteger[] encryptedMaskBigIntegers = rsa.Encrypt(mask, n, e);

            // Chuyển đổi BigInteger[] thành byte[]

            byte[] encryptedMaskBytes = new byte[encryptedMaskBigIntegers.Length * blockSize];
            for (int i = 0; i < encryptedMaskBigIntegers.Length; i++)
            {
                byte[] bytes = encryptedMaskBigIntegers[i].ToByteArray();
                Array.Copy(bytes, 0, encryptedMaskBytes, i * blockSize, Math.Min(bytes.Length, blockSize));
            }


            // Mã hóa aes key bằng mask (XOR)
            byte[] maskedAesKey = new byte[aesKeyByte.Length];
            for (int i = 0; i < aesKeyByte.Length; i++)
            {
                maskedAesKey[i] = (byte)(aesKeyByte[i] ^ mask[i]);
            }

            byte[] dataEncryptedByAes = aes.EncryptString(data, aesKeyByte);

            // Chuyển đổi sang base64
            var maskedAesKeyBase64 = Convert.ToBase64String(maskedAesKey);
            var encryptedMaskBase64 = Convert.ToBase64String(encryptedMaskBytes);
            var dataEncryptedByAesBase64 = Convert.ToBase64String(dataEncryptedByAes);
            Console.WriteLine($"n: {publicKeyFE.n}, e: {publicKeyFE.e}");
            Console.WriteLine("------------");
            Console.WriteLine($"n: {privateKeyFE.n}, d: {privateKeyFE.d}");

            // Tạo request object
            return new Request
            {
                DataEncryptedByAes = dataEncryptedByAesBase64,
                AesKeyMasked = maskedAesKeyBase64,
                MaskEncryptedByRsa = encryptedMaskBase64,
                PublicKeyFE = new PublicKey
                {
                    n = publicKeyFE.n.ToString(),
                    e = publicKeyFE.e.ToString()
                }
            };
        }

        public string DecryptResponseData(Response response)
        {
            const int blockSize = 16;
            var rsa = new CustomRSA();
            var aes = new CustomAES();

            // Chuyển đổi base64 thành byte[]
            byte[] dataEncryptedbyAesBytes = Convert.FromBase64String(response.DataEncryptedbyAes);
            byte[] aesKeyMaskedByte = Convert.FromBase64String(response.AesKeyMasked);
            byte[] maskEncryptedByRsaByte = Convert.FromBase64String(response.MaskEncryptedByRsa);

            // Chuyển đổi byte[] thành BigInteger
            BigInteger[] encryptedMask = new BigInteger[aesKeyMaskedByte.Length];
            for (int i = 0; i < aesKeyMaskedByte.Length; i++)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(maskEncryptedByRsaByte, i * blockSize, block, 0, blockSize);
                encryptedMask[i] = new BigInteger(block);
            }

            Console.WriteLine("------------");
            Console.WriteLine($"npk: {privateKeyFE.n}, dpk: {privateKeyFE.d}");

            // Giải mã mask
            byte[] decryptedMask = rsa.Decrypt(encryptedMask, BigInteger.Parse(privateKeyFE.n), BigInteger.Parse(privateKeyFE.d));

            // Đảm bảo độ dài mask bằng với dữ liệu
            if (decryptedMask.Length > aesKeyMaskedByte.Length)
            {
                Array.Resize(ref decryptedMask, aesKeyMaskedByte.Length);
            }

            // Giải mã dữ liệu bằng mask (XOR)
            byte[] originalAesKey = new byte[aesKeyMaskedByte.Length];
            for (int i = 0; i < aesKeyMaskedByte.Length; i++)
            {
                originalAesKey[i] = (byte)(aesKeyMaskedByte[i] ^ decryptedMask[i]);
            }

            // Giải mã dữ liệu bằng AES
            string originalData = aes.DecryptString(dataEncryptedbyAesBytes, originalAesKey);
            Console.WriteLine($"originalData: {originalData}");

            return originalData;
        }
    }
}
