using System;
using System.Data.SQLite;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableApp
{
    class Program
    {
        // ===========================
        // SAST kwetsbaarheden (SonarQube)
        // ===========================

        // 1. Hardcoded credentials (Security Hotspot)
        private const string DB_PASSWORD = "admin123";
        private const string SECRET_KEY = "supersecretkey123";
        private const string API_KEY = "sk-1234567890abcdef";

        // 2. SQL Injection
        static string GetUser(string username)
        {
            string connectionString = "Data Source=users.db;Version=3;";
            using var conn = new SQLiteConnection(connectionString);
            conn.Open();

            // FOUT: directe string concatenatie = SQL injection
            string query = "SELECT * FROM users WHERE username = '" + username + "'";
            using var cmd = new SQLiteCommand(query, conn);
            var result = cmd.ExecuteScalar();
            return result?.ToString() ?? "niet gevonden";
        }

        // 3. Command Injection
        static string PingHost(string host)
        {
            // FOUT: user input direct in shell commando
            var process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c ping " + host;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();
            return process.StandardOutput.ReadToEnd();
        }

        // 4. Insecure hashing (MD5 is broken)
        static string HashPassword(string password)
        {
            // FOUT: MD5 is cryptografisch onveilig
            using var md5 = MD5.Create();
            byte[] inputBytes = Encoding.UTF8.GetBytes(password);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            return Convert.ToHexString(hashBytes);
        }

        // 5. Path traversal
        static string ReadFile(string filename)
        {
            // FOUT: geen validatie van bestandspad
            string path = "C:\\data\\" + filename;
            return File.ReadAllText(path);
        }

        // 6. Insecure deserialization
        static object LoadData(byte[] data)
        {
            // FOUT: BinaryFormatter is onveilig en deprecated
            using var stream = new MemoryStream(data);
#pragma warning disable SYSLIB0011
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
#pragma warning restore SYSLIB0011
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
            Console.WriteLine("Welkom bij de kwetsbare .NET demo applicatie");

            // Simuleer een gebruiker opzoeken
            string user = GetUser("admin");
            Console.WriteLine($"Gebruiker gevonden: {user}");

            // Simuleer wachtwoord hashing
            string hashed = HashPassword("mijnwachtwoord");
            Console.WriteLine($"Wachtwoord hash (MD5): {hashed}");

            Console.WriteLine($"API Key: {API_KEY}");
        }
    }
}