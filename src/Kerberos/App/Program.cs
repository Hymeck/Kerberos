using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using DES;
using static System.Console;

namespace App
{
    class Program
    {
        static async Task Main(string[] args)
        {
            InputEncoding = Encoding.UTF8;
            OutputEncoding = Encoding.UTF8;
            
            var input = args.Length == 0 ? "abc" : args[0];
            WriteLine(input);
            
            // 1. normalize string
            var normalizedInput = Kerberos.normalizeLength(input);
            WriteLine(normalizedInput);
            
            // 2. to binary blocks
            var binaryBlocks = Kerberos.toBinaryBlocks(normalizedInput);
            WriteLine(string.Join(' ', binaryBlocks));

            var key = "хой";
            WriteLine(key);
            
            // 3. normalize key
            var normalizedKey = Kerberos.normalizeKey(
                key, 
                normalizedInput.Length / (2 * binaryBlocks.Count));
            WriteLine(normalizedKey);

            // 4. to binary key
            var binaryKey = Kerberos.toBinaryFormat(normalizedKey);
            WriteLine(binaryKey);

            // 5. DES encrypt
            var (encryptedBinaryBlocks, encryptedKey) = Kerberos.encrypt(binaryBlocks, binaryKey);
            WriteLine(string.Join("\t", encryptedKey, string.Join(' ', encryptedBinaryBlocks)));
            
            // 6. write result of the encryption
            await using var swEncrypted = new StreamWriter("outputEncrypted.txt");
            await swEncrypted.WriteAsync(Kerberos.fromListToNormalFormat(encryptedBinaryBlocks));
            
            // 7. write result of the decryption
            var (decryptedBinaryBlocks, decryptedKey) = Kerberos.decrypt(encryptedBinaryBlocks, encryptedKey);
            await using var swDecrypted = new StreamWriter("outputDecrypted.txt");
            await swDecrypted.WriteAsync(Kerberos.fromListToNormalFormat(decryptedBinaryBlocks));
            
            WriteLine(string.Join("\t", decryptedKey, string.Join(' ', decryptedBinaryBlocks)));
        }
    }
}
