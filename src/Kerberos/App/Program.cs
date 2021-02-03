using System;
using System.IO;
using System.Threading.Tasks;
using DES;
using static System.Console;

namespace App
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var input = "abc";
            WriteLine(input);
            
            var normalizedInput = Kerberos.normalizeLength(input);
            WriteLine(normalizedInput);
            
            // var blocks = Kerberos.toBlocks(normalizedInput);
            // foreach (var block in blocks) 
            //     WriteLine(block);

            var binaryInput = Kerberos.toBinaryFormat(normalizedInput);
            WriteLine(binaryInput);

            var decodedInput = Kerberos.fromBinaryFormat(binaryInput);
            WriteLine(decodedInput);

            var blocks = Kerberos.toBinaryBlocks(normalizedInput);

            var key = "хой";
            WriteLine(key);
            var normalizedKey = Kerberos.normalizeKey(
                key, 
                normalizedInput.Length / (2 * blocks.Count));

            var binaryKey = Kerberos.toBinaryFormat(normalizedKey);

            var (encryptedBinaryBlocks, encryptedKey) = Kerberos.encrypt(blocks, binaryKey);
            await using var swEncrypted = new StreamWriter("outputEncrypted.txt");
            await swEncrypted.WriteAsync(string.Join(string.Empty, encryptedBinaryBlocks));
            
            var (decryptedBinaryBlocks, decryptedKey) = Kerberos.decrypt(encryptedBinaryBlocks, encryptedKey);

            await using var swDecrypted = new StreamWriter("outputDecrypted.txt");
            await swDecrypted.WriteAsync(string.Join(string.Empty, decryptedBinaryBlocks));
            
            WriteLine(decryptedKey);
        }
    }
}
