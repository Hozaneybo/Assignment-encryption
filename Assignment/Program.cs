
using System.Security.Cryptography;
using System.Text;


Console.WriteLine("Passphrase:");
        string passphrase = Console.ReadLine();

        while (true)
        {
            Console.WriteLine("1: Safely store message\n2: Read message\n0: Exit");
            string option = Console.ReadLine();

            if (option == "1")
            {
                Console.WriteLine("Type a message to encrypt:");
                string message = Console.ReadLine();
                byte[] encryptedMessage = Encrypt(message, passphrase);
                string directoryPath = "encryptedMessage";
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }
                File.WriteAllBytes("encryptedMessage.txt", encryptedMessage);
            }
            else if (option == "2")
            {
                byte[] encryptedMessage = File.ReadAllBytes("encryptedMessage.txt");
                string decryptedMessage = Decrypt(encryptedMessage, passphrase);
                Console.WriteLine(decryptedMessage);
            }
            else if (option == "0")
            {
                break;
            }
        }
    

    static byte[] Encrypt(string message, string passphrase)
    {
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] key = Encoding.UTF8.GetBytes(passphrase.Substring(0, 16));
        using (AesGcm aes = new AesGcm(key))

        {
            byte[] ciphertext = new byte[messageBytes.Length];
            byte[] tag = new byte[16];
            byte[] nonce = new byte[12];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }
            aes.Encrypt(nonce, messageBytes, ciphertext, tag);
            return Concat(Concat(nonce, ciphertext), tag);
        }
    }

    static string Decrypt(byte[] encryptedMessage, string passphrase)
    {
        byte[] nonce = new byte[12];
        Array.Copy(encryptedMessage, nonce, 12);
        byte[] ciphertext = new byte[encryptedMessage.Length - 28];
        Array.Copy(encryptedMessage, 12, ciphertext, 0, ciphertext.Length);
        byte[] tag = new byte[16];
        Array.Copy(encryptedMessage, encryptedMessage.Length - 16, tag, 0, 16);

        byte[] key = Encoding.UTF8.GetBytes(passphrase.Substring(0, 16));
        using (AesGcm aes = new AesGcm(key))

        {
            byte[] decryptedMessage = new byte[ciphertext.Length];
            aes.Decrypt(nonce, ciphertext, tag, decryptedMessage);
            return Encoding.UTF8.GetString(decryptedMessage);
        }
    }

    static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.Length + b.Length];
        Array.Copy(a, c, a.Length);
        Array.Copy(b, 0, c, a.Length, b.Length);
        return c;
    }
