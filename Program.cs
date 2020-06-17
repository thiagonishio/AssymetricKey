using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AssymetricKey
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create an instance of the RSA algorithm class  
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            // Get the public keyy   
            string publicKey = rsa.ToXmlString(false); // false to get the public key   
            string privateKey = rsa.ToXmlString(true); // true to get the private key

            // Call the encryptText method   
            EncryptText(publicKey, "Hello from Plataforma", "encryptedData.dat");

            Console.WriteLine("Public Key: {0}", publicKey);
            Console.WriteLine("");
            Console.WriteLine("Private Key: {0}", privateKey);
            Console.WriteLine("");

            // Call the decryptData method and print the result on the screen   
            Console.WriteLine("Decrypted message: {0}", DecryptData(privateKey, "encryptedData.dat"));
            Console.WriteLine("");

            Console.WriteLine("TESTE CHAVE PRIVADA, IMPORTANDO FORMATO PEM");
            Console.WriteLine("");


            string chavepublica = rsa.ExportPemPublicKey();
            string chaveprivada = rsa.ExportPemPrivateKey();

            Console.WriteLine("Public Key: {0}", chavepublica);
            Console.WriteLine("");
            Console.WriteLine("Private Key: {0}", chaveprivada);
            Console.WriteLine("");

            rsa.ImportPemPrivateKey(PRIVATKEY);

            privateKey = rsa.ToXmlString(true); // true to get the private key

            // Call the decryptData method and print the result on the screen   
            Console.WriteLine("Decrypted message with PEM: {0}", DecryptData(privateKey, "encryptedData.dat"));
            Console.WriteLine("");
        }

        const string PUBLICKEY = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuBguvZ1eFy+JDkaW3qjV
DJA7TEkk+MCgCT9eQuHUGteA9LJjHYCBWqWFm5mYQEbak47hVAb+S/XDv8dSZys7
X8UthQbAJBhq7vaCue66sfXbrkcpjiKeZGBfv75zX3flbZKsA8c5rNrU6MloL6Vm
5ASGD6nEMCrlPfJCIDeNPaXkJDF8nxRImd86HZTmbvs1kbqE3iekjKQ+w4+0eGim
mMT2I3fzTLJ+kLBmm2Lf0IWX9fG/K333Qmb87vSimHkLa0wq+lbdqz+Shx7opI6j
eZk3fadfxRgxZlyNczio7knBD6GUZuMabrXC3dL+keb+BUiaOcJ64eZpLajKdx5h
rQIDAQAB
-----END PUBLIC KEY-----";
        /*
        const string PRIVATKEY = @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuBguvZ1eFy+JDkaW3qjVDJA7TEkk+MCgCT9eQuHUGteA9LJj
HYCBWqWFm5mYQEbak47hVAb+S/XDv8dSZys7X8UthQbAJBhq7vaCue66sfXbrkcp
jiKeZGBfv75zX3flbZKsA8c5rNrU6MloL6Vm5ASGD6nEMCrlPfJCIDeNPaXkJDF8
nxRImd86HZTmbvs1kbqE3iekjKQ+w4+0eGimmMT2I3fzTLJ+kLBmm2Lf0IWX9fG/
K333Qmb87vSimHkLa0wq+lbdqz+Shx7opI6jeZk3fadfxRgxZlyNczio7knBD6GU
ZuMabrXC3dL+keb+BUiaOcJ64eZpLajKdx5hrQIDAQABAoIBAGcBsPWL3h/fCzMf
sD85/Kug8G0I6FT/gwxplpaZwZKbTp6cSfUx+C7+OroLwTMF8jtqUQ4xM4zRIQxn
vOXZPMmjjIrIci5AM2UuLYtX1sLIrHjhfJD5MeM8QZcKO4gJkCg1T2Z1zQG5GDSA
rXkrdVzUYybUeN/ywH5e1T0tmCwLeGk5Zad4yw6lwXHZMrjvk2cYWJUn9PCCufIc
skRHYBbxx0jh/V8u38JCW88afBDKDci5W+/o9RZDFaMEGHdiWvzle+1y10unubUu
69s0D/Fw5dLhkTXSqegxbDXUMoQdbfqGLHzWGdqL5BxV0yIQSaKv7l6XIBDu4sig
8EADrokCgYEA7/G9fF2CWAlUGkgKLRGUoQiytBuzj48d3K1CYFvR7iBDUjatkaZY
FAKlEBPxMw5d9jsNqM0JpPMlN/fqOQgH7giGPwl6MgSnKXeXSN21smOS9o8TizKa
2gll97KxlbYlD7yGWHZnizAabEzNz5GvR+rbG1pzz8Qb52yTwRpzADsCgYEAxGm7
QkALiMW023MBRkk8qa7+9y//l+Je1qrCahFS2NG9piPu2XBRLjcu/1Z9bEkHyyal
ADOq3ZNgy2MRwpsadjSm8oZLvGbyoC2AqeJ3LuahWk2Yeqw8sogKs7FOSagJwjSY
+N7/Zr/J1AfeTVeDrsQksD1VWhB+Ak8jIeazrzcCgYB5ALYIM7f54apyHoZTOBx2
IUbNoXKqIQh0M0PYCDYUGl0Y5s4dN4APh03qj8QBdWtZM2quB8inUJ8iXHnYDP7C
wbXBsGvZMZODS/YVHwn0Tlbc1EaM2hZRgo/TnGAGGfcSuoYdsoiBHt8UYp8f4F4+
rGeWocTpsAJKcO0KYuY/5QKBgDa7F7kwS4aDQRBdjZ9eTQ8jely6/Uf/hlnfH2mb
BjDw0R34qVfh2l08d1YjbbO87fUIAbZ6r0QrCy/hnVNTER6bMWInVfdb4IQN6eps
9rUVAyU8th6I3CkLi5/i6mPP9Vgue+ntidHB46W3w5RdrI4IjgimLqB4NATEtI9/
z9YlAoGBANp3O5iOZrMLM6pmUBqovxBgGVgjyOYqdqFDKlPY4ipuRGbXqj5X1nSE
mjh+gAzaey9xiZdq53BEHTPWIhfmbEyuJjfAEfHNCAATTaLwvcX94+3lIeGpBHil
zmXWjPiqMTZEkc5dPvygrHMkf19scBnWMWRRKn/8JclpmeV5p9cg
-----END RSA PRIVATE KEY-----";
        */

        const string PRIVATKEY = @"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAuBguvZ1eFy+JDkaW3qjVDJA7TEkk+MCgCT9eQuHUGteA9LJj\nHYCBWqWFm5mYQEbak47hVAb+S/XDv8dSZys7X8UthQbAJBhq7vaCue66sfXbrkcp\njiKeZGBfv75zX3flbZKsA8c5rNrU6MloL6Vm5ASGD6nEMCrlPfJCIDeNPaXkJDF8\nnxRImd86HZTmbvs1kbqE3iekjKQ+w4+0eGimmMT2I3fzTLJ+kLBmm2Lf0IWX9fG/\nK333Qmb87vSimHkLa0wq+lbdqz+Shx7opI6jeZk3fadfxRgxZlyNczio7knBD6GU\nZuMabrXC3dL+keb+BUiaOcJ64eZpLajKdx5hrQIDAQABAoIBAGcBsPWL3h/fCzMf\nsD85/Kug8G0I6FT/gwxplpaZwZKbTp6cSfUx+C7+OroLwTMF8jtqUQ4xM4zRIQxn\nvOXZPMmjjIrIci5AM2UuLYtX1sLIrHjhfJD5MeM8QZcKO4gJkCg1T2Z1zQG5GDSA\nrXkrdVzUYybUeN/ywH5e1T0tmCwLeGk5Zad4yw6lwXHZMrjvk2cYWJUn9PCCufIc\nskRHYBbxx0jh/V8u38JCW88afBDKDci5W+/o9RZDFaMEGHdiWvzle+1y10unubUu\n69s0D/Fw5dLhkTXSqegxbDXUMoQdbfqGLHzWGdqL5BxV0yIQSaKv7l6XIBDu4sig\n8EADrokCgYEA7/G9fF2CWAlUGkgKLRGUoQiytBuzj48d3K1CYFvR7iBDUjatkaZY\nFAKlEBPxMw5d9jsNqM0JpPMlN/fqOQgH7giGPwl6MgSnKXeXSN21smOS9o8TizKa\n2gll97KxlbYlD7yGWHZnizAabEzNz5GvR+rbG1pzz8Qb52yTwRpzADsCgYEAxGm7\nQkALiMW023MBRkk8qa7+9y//l+Je1qrCahFS2NG9piPu2XBRLjcu/1Z9bEkHyyal\nADOq3ZNgy2MRwpsadjSm8oZLvGbyoC2AqeJ3LuahWk2Yeqw8sogKs7FOSagJwjSY\n+N7/Zr/J1AfeTVeDrsQksD1VWhB+Ak8jIeazrzcCgYB5ALYIM7f54apyHoZTOBx2\nIUbNoXKqIQh0M0PYCDYUGl0Y5s4dN4APh03qj8QBdWtZM2quB8inUJ8iXHnYDP7C\nwbXBsGvZMZODS/YVHwn0Tlbc1EaM2hZRgo/TnGAGGfcSuoYdsoiBHt8UYp8f4F4+\nrGeWocTpsAJKcO0KYuY/5QKBgDa7F7kwS4aDQRBdjZ9eTQ8jely6/Uf/hlnfH2mb\nBjDw0R34qVfh2l08d1YjbbO87fUIAbZ6r0QrCy/hnVNTER6bMWInVfdb4IQN6eps\n9rUVAyU8th6I3CkLi5/i6mPP9Vgue+ntidHB46W3w5RdrI4IjgimLqB4NATEtI9/\nz9YlAoGBANp3O5iOZrMLM6pmUBqovxBgGVgjyOYqdqFDKlPY4ipuRGbXqj5X1nSE\nmjh+gAzaey9xiZdq53BEHTPWIhfmbEyuJjfAEfHNCAATTaLwvcX94+3lIeGpBHil\nzmXWjPiqMTZEkc5dPvygrHMkf19scBnWMWRRKn/8JclpmeV5p9cg\n-----END RSA PRIVATE KEY-----";

        // Create a method to encrypt a text and save it to a specific file using a RSA algorithm public key   
        static void EncryptText(string publicKey, string text, string fileName)
        {
            // Convert the text to an array of bytes   
            UnicodeEncoding byteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = byteConverter.GetBytes(text);

            // Create a byte array to store the encrypted data in it   
            byte[] encryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Set the rsa pulic key   
                rsa.FromXmlString(publicKey);

                // Encrypt the data and store it in the encyptedData Array   
                encryptedData = rsa.Encrypt(dataToEncrypt, false);
            }
            // Save the encypted data array into a file   
            File.WriteAllBytes(fileName, encryptedData);

            Console.WriteLine("Data has been encrypted");
        }

        // Method to decrypt the data withing a specific file using a RSA algorithm private key   
        static string DecryptData(string privateKey, string fileName)
        {
            // read the encrypted bytes from the file   
            byte[] dataToDecrypt = File.ReadAllBytes(fileName);

            // Create an array to store the decrypted data in it   
            byte[] decryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Set the private key of the algorithm   
                rsa.FromXmlString(privateKey);
                decryptedData = rsa.Decrypt(dataToDecrypt, false);
            }

            // Get the string value from the decryptedData byte array   
            UnicodeEncoding byteConverter = new UnicodeEncoding();
            return byteConverter.GetString(decryptedData);
        }
    }

    public static class RSACryptoServiceProviderExtension
    {
        /// <summary>
        /// Import OpenSSH PEM private key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static void ImportPemPrivateKey(this RSACryptoServiceProvider csp, string pem)
        {
            csp = new RSACryptoServiceProvider(2048);
            PemReader pr = new PemReader(new StringReader(pem?.Replace("\\n", "\n")));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

            csp.ImportParameters(rsaParams);
        }

        /// <summary>
        /// Import OpenSSH PEM public key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static void ImportPemPublicKey(this RSACryptoServiceProvider csp, string pem)
        {
            csp = new RSACryptoServiceProvider(2048);
            PemReader pr = new PemReader(new StringReader(pem?.Replace("\\n", "\n")));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

            csp.ImportParameters(rsaParams);
        }

        

        public static string ExportPemPrivateKey(this RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END RSA PRIVATE KEY-----");
            }

            return outputStream.ToString();
        }


        /// <summary>
        /// Export public key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/28407693
        /// </summary>
        /// <param name="csp"></param>
        /// <returns></returns>
        public static string ExportPemPublicKey(this RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END PUBLIC KEY-----");
            }

            return outputStream.ToString();
        }

        /// <summary>
        /// https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="length"></param>
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        /// <summary>
        /// https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="value"></param>
        /// <param name="forceUnsigned"></param>
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

    }
}
