using System;
using System.Numerics;
using System.Text;

namespace UserManagementFE.Utils
{
    public class CustomRSA
    {
        private BigInteger n;
        private BigInteger e;
        private BigInteger d;

        public CustomRSA(int bitLength = 128)
        {
            GenerateKeys(bitLength);
        }

        private static bool IsPrime(BigInteger n, int k = 5)
        {
            if (n <= 1) return false;
            if (n <= 3) return true;
            if (n % 2 == 0) return false;

            BigInteger r = 0, d = n - 1;
            while (d % 2 == 0)
            {
                r++;
                d /= 2;
            }

            Random rand = new Random();
            for (int i = 0; i < k; i++)
            {
                BigInteger a = 2 + rand.Next(0, 100) % (n - 4);
                BigInteger x = ModPow(a, d, n);

                if (x == 1 || x == n - 1) continue;

                for (BigInteger j = 0; j < r - 1; j++)
                {
                    x = ModPow(x, 2, n);
                    if (x == n - 1) break;
                }

                if (x != n - 1) return false;
            }
            return true;
        }

        private static BigInteger GeneratePrime(int bitLength, Random rand)
        {
            while (true)
            {
                byte[] bytes = new byte[bitLength / 8];
                rand.NextBytes(bytes);
                bytes[bytes.Length - 1] &= 0x7F;
                BigInteger num = new BigInteger(bytes);
                num |= 1;
                if (IsPrime(num, 5)) return num;
            }
        }

        private static BigInteger GCD(BigInteger a, BigInteger b)
        {
            while (b != 0)
            {
                BigInteger temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        private static BigInteger ModInverse(BigInteger e, BigInteger phi)
        {
            BigInteger m0 = phi, t, q;
            BigInteger x0 = 0, x1 = 1;

            if (phi == 1) return 0;

            while (e > 1)
            {
                q = e / phi;
                t = phi;
                phi = e % phi;
                e = t;
                t = x0;
                x0 = x1 - q * x0;
                x1 = t;
            }

            if (x1 < 0) x1 += m0;
            return x1;
        }

        private static BigInteger ModPow(BigInteger baseNum, BigInteger exp, BigInteger modulus)
        {
            BigInteger result = 1;
            baseNum %= modulus;

            while (exp > 0)
            {
                if ((exp & 1) == 1)
                    result = (result * baseNum) % modulus;
                baseNum = (baseNum * baseNum) % modulus;
                exp >>= 1;
            }
            return result;
        }

        private void GenerateKeys(int bitLength)
        {
            Random rand = new Random();
            BigInteger p = GeneratePrime(bitLength / 2, rand);
            BigInteger q = GeneratePrime(bitLength / 2, rand);

            n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            e = 65537;
            while (GCD(e, phi) != 1)
            {
                e++;
            }

            d = ModInverse(e, phi);
        }

        public (BigInteger n, BigInteger e) GetPublicKey()
        {
            return (n, e);
        }

        public (BigInteger n, BigInteger d) GetPrivateKey()
        {
            return (n, d);
        }

        public BigInteger[] Encrypt(byte[] data, BigInteger n, BigInteger e)
        {
            BigInteger[] encrypted = new BigInteger[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                BigInteger m = data[i];
                if (m < 0 || m > 255)
                {
                    throw new Exception($"Dữ liệu đầu vào tại vị trí {i} là {m}, không nằm trong phạm vi byte (0-255).");
                }
                if (m >= n) throw new Exception($"Dữ liệu tại vị trí {i} lớn hơn modulus n.");
                encrypted[i] = ModPow(m, e, n);
            }
            return encrypted;
        }

        public byte[] Decrypt(BigInteger[] encrypted, BigInteger n, BigInteger d)
        {
            byte[] decrypted = new byte[encrypted.Length];
            for (int i = 0; i < encrypted.Length; i++)
            {
                BigInteger c = encrypted[i];
                BigInteger m = ModPow(c, d, n);
                if (m < 0 || m > 255)
                {
                    throw new Exception($"Giải mã thất bại: Giá trị tại vị trí {i} là {m}, không nằm trong phạm vi byte (0-255).");
                }
                decrypted[i] = (byte)m;
            }
            return decrypted;
        }
    }
}