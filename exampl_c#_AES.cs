using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Net.Http;
using System.Collections.Generic;

namespace Aes_Example
{
    class AesExample
    {
        public static async void Main()
        {
            string original = "hello world";

            // Create a new instance of the Aes
            // class.  This generates a new key and initialization
            // vector (IV).
            using (Aes myAes = Aes.Create())
            {
                byte[] key = PackH("d9d359cce9371de02914c42d2786c0d9");
                byte[] iv = StringToByteArray("bb78c8065a90e05f1520b8ca17de1295");

                // Encrypt the string to an array of bytes.
                byte[] encrypted = EncryptStringToBytes_Aes(original, key, iv);

                // Decrypt the bytes to a string.
                string roundtrip = DecryptStringFromBytes_Aes(encrypted, key, iv);

                //Display the original data and the decrypted data.
                string base64String = Convert.ToBase64String(encrypted, 0, encrypted.Length);
                string str = Encoding.Default.GetString(encrypted);

                Console.WriteLine("The String is: " + base64String);
                Console.WriteLine("Round Trip: {0}", roundtrip);


                HttpClient client = new HttpClient();
                var values = new Dictionary<string, string>
                {
                    { "thing1", "hello" },
                    { "thing2", "world" }
                };

                var content = new FormUrlEncodedContent(values);

                var response = await client.PostAsync("https://www.google.com", content);
            Console.WriteLine("LKL");
                var responseString = await response.Content.ReadAsStringAsync();

            }
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            byte[] pt = Encoding.ASCII.GetBytes(plainText);
            // Create an Aes object
            // with the specified key and IV.

            using (Aes amAes = new AesManaged())
            {
                amAes.Mode = CipherMode.CBC;
                amAes.Padding = PaddingMode.PKCS7;
                amAes.KeySize = 128;
                amAes.BlockSize = 128;
                amAes.Key = Key;
                amAes.IV = IV;
                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = amAes.CreateEncryptor(amAes.Key, amAes.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes amAes = new AesManaged())
            {
                amAes.Mode = CipherMode.CBC;
                amAes.Padding = PaddingMode.PKCS7;
                amAes.KeySize = 128;
                amAes.BlockSize = 128;
                amAes.Key = Key;
                amAes.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = amAes.CreateDecryptor(amAes.Key, amAes.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        private static byte[] PackH(string hex)
        {
            if ((hex.Length % 2) == 1) hex += '0';
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }

        private static byte[] StringToByteArray(string hex) {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}