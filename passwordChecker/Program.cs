using System;
using System.Text;
using System.Security.Cryptography;

namespace passwordChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //new SqlServerBackedData().Implement();
                //new PostgresBackedData().Implement();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }

            Console.WriteLine("The End!");
            Console.ReadLine();
        }

        public static string GetPasswordFromConsole()
        {
            var pass = new StringBuilder();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);

                // Backspace Should Not Work
                if (!char.IsControl(key.KeyChar))
                {
                    pass.Append(key.KeyChar);
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && pass.Length > 0)
                    {
                        pass.Remove(pass.Length - 1, 1);
                        Console.Write("\b \b");
                    }
                }
            }
            // Stops Receving Keys Once Enter is Pressed
            while (key.Key != ConsoleKey.Enter);
            return pass.ToString();
        }

        public static string SHA1HashStringForUTF8String(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s);

            var sha1 = SHA1.Create();
            byte[] hashBytes = sha1.ComputeHash(bytes);

            return HexStringFromBytes(hashBytes);
        }

        public static string HexStringFromBytes(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (byte b in bytes)
            {
                var hex = b.ToString("x2");
                sb.Append(hex);
            }
            return sb.ToString();
        }
    }
}