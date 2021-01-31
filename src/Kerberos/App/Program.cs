using Library;
using static System.Console;

namespace App
{
    class Program
    {
        static void Main(string[] args)
        {
            var input = "0";
            WriteLine(input);
            
            var normalizedInput = Kerberos.normalizeLength(input);
            WriteLine(normalizedInput);
            
            var blocks = Kerberos.toBlocks(normalizedInput);
            foreach (var block in blocks) 
                WriteLine(block);
        }
    }
}
